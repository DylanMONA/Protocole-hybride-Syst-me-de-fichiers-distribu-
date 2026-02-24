package UI

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"myp2p/client"
	"myp2p/clientStorage"
	"net"
	"strings"
	"time"

	"fyne.io/fyne/v2/widget"
)

// -----------------------------
// UpdateMyMerkle
// -----------------------------
// Reconstruit le Merkle tree local à partir des fichiers dans DATA_DIRECTORY
// - Recalcule la racine
// - Supprime l'ancien Merkle tree si la racine a changé
// - Log l'action
func UpdateMyMerkle(logger *Logger) {
	// reconstruction du Merkle tree à partir du répertoire de données
	racine, err := clientStorage.BuildMerkleNode(DATA_DIRECTORY)
	if err != nil {
		logger.Error("Erreur répertoire: " + err.Error())
		return
	}

	// sauvegarde de l'ancienne racine
	oldroot := clientStorage.RootHash
	clientStorage.RootHash = clientStorage.Sha(racine)
	if bytes.Equal(oldroot, clientStorage.RootHash) {
		logger.Warn("vos données non pas changé")
		return
	}
	client.MyListroots = client.AddListRoot(client.MyListroots, clientStorage.RootHash)

	logger.Info("Merkle mis à jour")
}

// -----------------------------
// AskMerkleSelectedPeers
// -----------------------------
// Envoie des requêtes DatumRequest pour récupérer le Merkle tree de peers sélectionnés
// - Vérifie si des peers sont sélectionnés
// - Vérifie que le peer existe, a un ActiveAddr et une racine connue
// - Crée une transaction et envoie le message
// - Démarre le suivi de téléchargement Merkle pour le peer
func AskMerkleSelectedPeers(peerChecks *widget.CheckGroup, conn *net.UDPConn, priv *ecdsa.PrivateKey, logger *Logger) {
	if len(peerChecks.Selected) == 0 {
		logger.Warn("Sélectionnez au moins un peer")
		return
	}

	logger.Warn("ASK MERKLE demande le merkleTree d'un peer ou plusieurs")
	logger.Warn("Une demande de merkleTree peut prendre du temps.")

	for _, name := range peerChecks.Selected {
		peer, ok := client.FindPeer(name)
		if !ok {
			logger.Error("Peer introuvable ou invalide")
			continue
		}

		// le peer doit être connecté et avoir un handshake complet
		if peer.ActiveAddr == nil {
			logger.Error("Handshake requis pour " + name)
			continue
		}

		// la racine doit être connue
		if peer.Root == nil {
			logger.Warn("Root inconnu pour " + name)
			continue
		}
		// marquer le peer comme en train de télécharger son Merkle
		client.StartAskMerkle(peer)

		// si le root du peer n'a pas changé on dit directement : " C'est bon téléchargé ! "
		if peer.RootChanged == false {
			peer.MerkleDone = true

			if client.OnPeerEvent != nil {
				duration := time.Since(peer.MerkleDownloadStart)
				client.OnPeerEvent(peer, client.EventMerkleDownloadComplete, fmt.Sprintf("durée: %s", duration.Round(time.Millisecond)))
			}
			continue
		}

		// création de la requête DatumRequest
		id := client.GenerateId()
		msg, err := client.BuildDatumRequest(id, peer.Root)
		if err != nil {
			logger.Error("Erreur MERKLE pour " + name)
			continue
		}

		// création d'une transaction pour suivre la requête
		client.CreateTransaction(id, peer, peer.ActiveAddr, client.DatumRequest, msg, client.Retries)

		// envoi de la requête
		client.SendMessage(conn, peer.ActiveAddr, msg)
		logger.Info("→ Requête MERKLE envoyée à " + name)
		peer.RootChanged = false // On a récupéré les changements
	}
}

// -----------------------------
// PrintPeerMerkle
// -----------------------------
// Affiche le Merkle tree d’un peer dans l’interface via le Logger
// - Vérifie que la racine existe et est trouvable
// - Lance un affichage récursif dans une goroutine pour ne pas bloquer l'UI
func PrintPeerMerkle(peer *client.Peer, log Logger) {
	if peer.Root == nil {
		log.Warn("Root inconnu pour " + peer.Name)
		return
	}

	log.Info("Affichage Merkle du peer " + peer.Name)

	hash, ok := clientStorage.FindHash(peer.Root)
	if !ok {
		log.Error("Hash introuvable pour le root")
		return
	}

	// affichage récursif
	go PrintTreeGUI(
		hash,
		0,
		log.Info,
	)
}

// -----------------------------
// PrintTreeGUI
// -----------------------------
// Affiche récursivement l’arborescence du Merkle tree
// - node : le nœud courant
// - depth : profondeur pour l’indentation
// - log : fonction de logging
func PrintTreeGUI(node []byte, depth int, log func(string)) {
	prefix := strings.Repeat("  ", depth) // indentation selon la profondeur
	if len(node) == 0 {
		log(prefix + "<empty>")
		return
	}

	switch node[0] {

	case clientStorage.Directory:
		log(prefix + "Directory:")
		offset := clientStorage.IdSize
		for offset+clientStorage.DirEntrySize <= len(node) {
			name := strings.TrimRight(string(node[offset:offset+clientStorage.NameSize]), "\x00") // nom du fichier/dossier
			hash := node[offset+clientStorage.NameSize : offset+clientStorage.DirEntrySize]       // hash associé
			offset += clientStorage.DirEntrySize
			log(prefix + "  " + name)
			if child, ok := clientStorage.FindHash(hash); ok {
				PrintTreeGUI(child, depth+1, log)
			}
		}

	case clientStorage.Big, clientStorage.BigDirectory:
		offset := clientStorage.IdSize
		for offset+clientStorage.HashSize <= len(node) {
			hash := node[offset : offset+clientStorage.HashSize]
			offset += clientStorage.HashSize
			if child, ok := clientStorage.FindHash(hash); ok {
				PrintTreeGUI(child, depth+1, log)
			}
		}
	}
}
