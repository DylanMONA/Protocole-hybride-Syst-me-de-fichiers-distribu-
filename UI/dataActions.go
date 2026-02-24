package UI

import (
	"crypto/ecdsa"
	"fmt"
	"myp2p/client"
	"myp2p/clientStorage"
	"net"

	"fyne.io/fyne/v2/widget"
)

//-------------------------------- Constantes pour les versions -----------------------------------------------------

const (
	LATEST_VERSION      = "Latest version"      // Dernière version
	PREVIOUS_VERSION    = "Previous version"    // Version précédente
	SECOND_LAST_VERSION = "Second-last version" // Avant-dernière version
)

//-------------------------------------------------------------------------------------------------------------------

// ASK ROOT
func AskRootSelectedPeers(peerChecks *widget.CheckGroup, conn *net.UDPConn, priv *ecdsa.PrivateKey, logger *Logger) {
	if len(peerChecks.Selected) == 0 {
		logger.Warn("Sélectionnez au moins un peer")
		return
	}
	logger.Warn("ASK ROOT demande le hashroot d'un peer ou plusieurs")

	for _, name := range peerChecks.Selected {
		peer, ok := client.FindPeer(name)
		if !ok {
			logger.Error("Peer introuvable ou invalide")
			continue
		}
		if peer.ActiveAddr == nil {
			logger.Error("Handshake requis pour " + name)
			continue
		}

		if client.IsBan(name) {
			logger.Warn(name + " est Ban")
			id := client.GenerateId()
			msg, err := client.BuildMessage(id, client.Error, []byte{}, nil, false)
			if err != nil {
				logger.Error("Erreur send error ban pour " + name)
				continue
			}
			client.SendMessage(conn, peer.ActiveAddr, msg)
			continue
		}

		id := client.GenerateId()
		msg, err := client.BuildMessage(id, client.RootRequest, []byte{}, priv, false)
		if err != nil {
			logger.Error("Erreur ROOT pour " + name)
			continue
		}

		client.CreateTransaction(id, peer, peer.ActiveAddr, client.RootRequest, msg, client.Retries)
		client.SendMessage(conn, peer.ActiveAddr, msg)
		logger.Info("→ Requête ROOT envoyée à " + name)
	}
}

//-----------------------------------------------------------------------------------------------------

// AskDataPeer gère le téléchargement d'un fichier ou de toutes les données pour un ou plusieurs peers
func AskDataPeer(peerChecks *widget.CheckGroup, filename string, version string, logger *Logger) {
	if len(peerChecks.Selected) == 0 {
		logger.Warn("Sélectionner au moins un peer avant de demander des données !")
		return
	}
	// Cas plusieurs peers sélectionnés : on ne peut télécharger que tout le root
	if len(peerChecks.Selected) > 1 {
		if filename != "" {
			logger.Warn("Impossible de télécharger un fichier spécifique pour plusieurs peers. Sélectionnez un seul peer ou laissez vide pour tout télécharger.")
			return
		}
		for _, name := range peerChecks.Selected {
			peer, ok := client.FindPeer(name)
			if !ok {
				logger.Error("Peer introuvable ou invalide : " + name)
				continue
			}
			if peer.Root == nil {
				logger.Warn("Root inconnu pour " + name)
				continue
			}
			root := selectVersionRoot(peer, version)
			go DownloadFileGUI(root, "", name, *logger, version)
			logger.Info("→ Téléchargement complet depuis " + name + " (version : " + version + ")")
		}
		return
	}

	// Cas un seul peer sélectionné
	peer, ok := client.FindPeer(peerChecks.Selected[0])
	if !ok {
		logger.Error("Peer introuvable ou invalide")
		return
	}
	if peer.Root == nil {
		logger.Warn("Faites la demande de hashroot avant bouton 'ROOT'")
		return
	}

	// Sélection de la version
	root := selectVersionRoot(peer, version)

	if filename != "" {
		// Télécharger un seul fichier
		hash, found := clientStorage.FindName([]byte(filename))
		if !found {
			logger.Error("Fichier introuvable dans le Merkle")
			return
		}
		logger.Info(fmt.Sprintf("→ Téléchargement du fichier %s depuis %s (version : %s)", filename, peer.Name, version))
		go DownloadFileGUI(hash, filename, peer.Name, *logger, LATEST_VERSION)
	} else {
		// Télécharger tout le root
		logger.Info(fmt.Sprintf("→ Téléchargement complet depuis %s (version : %s)", peer.Name, version))
		go DownloadFileGUI(root, "", peer.Name, *logger, version)
	}
}

// selectVersionRoot retourne le root correspondant à la version sélectionnée
func selectVersionRoot(peer *client.Peer, version string) []byte {
	switch version {
	case LATEST_VERSION:
		return peer.Root
	case PREVIOUS_VERSION:
		if len(peer.Listroots) > 1 && peer.Listroots[1] != nil {
			if len(peer.Listroots) > 2 {
				return peer.Listroots[1]
			} else {
				return peer.Listroots[0]
			}

		}
	case SECOND_LAST_VERSION:
		if len(peer.Listroots) > 2 && peer.Listroots[2] != nil {
			return peer.Listroots[0]
		}
	}
	// par défaut, on retourne la dernière version si la version demandée est indisponible
	return peer.Root
}
