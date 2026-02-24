package client

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"myp2p/clientStorage"
	"net"
	"time"
)

// --------------------------------------------
// CONSTANTES ET STRUCTURES
// --------------------------------------------

// DatumJob représente une requête pour un hash spécifique depuis un peer donné.
type DatumJob struct {
	Hash []byte       // le hash de la donnée demandée
	Addr *net.UDPAddr // adresse UDP du peer à interroger
}

// DatumQueue : canal global des jobs de données à traiter.
// On utilise un buffer important (8192) pour éviter les blocages si plusieurs jobs arrivent rapidement.
var DatumQueue = make(chan DatumJob, 8192)
var debugDatum = true

// --------------------------------------------
// DatumScheduler
// --------------------------------------------
// Lit en boucle le canal DatumQueue et envoie des requêtes DatumRequest aux peers.
//
// Paramètres :
// - conn : connexion UDP utilisée pour envoyer les messages
//
// Fonctionnement :
// 1. Récupère un job dans DatumQueue.
// 2. Cherche le peer correspondant à l'adresse.
// 3. Attend une place libre dans la "fenêtre" du peer (limitation du nombre de requêtes simultanées).
// 4. Génère un ID de transaction unique.
// 5. Construit le message DatumRequest.
// 6. Met à jour la fenêtre du peer et crée une transaction pour le suivi.
// 7. Envoie le message UDP.
func DatumScheduler(conn *net.UDPConn) {
	for job := range DatumQueue {
		peer, ok := FindPeerByAddr(job.Addr)
		if !ok {
			continue // le peer n'existe pas → on ignore
		}

		// attendre qu'il y ait de la place dans la fenêtre du peer
		for !peer.Window.CanSend() {
			if debugSlidingWindow {
				fmt.Println("boucle infini !")
			}
			time.Sleep(200 * time.Microsecond)
		}

		id := GenerateId()
		msg, err := BuildDatumRequest(id, job.Hash)
		if err != nil {
			fmt.Println("Erreur BuildDatumRequest:", err)
			continue
		}

		peer.Window.OnSend()

		// crée une transaction pour suivre la réponse
		CreateTransaction(
			id,
			peer,
			job.Addr,
			DatumRequest,
			msg,
			Retries+2,
		)

		SendMessage(conn, job.Addr, msg)
	}
}

// --------------------------------------------
// HandlefileDataWindow
// --------------------------------------------
// Analyse le body d'une donnée reçue et programme de nouvelles requêtes si nécessaire.
//
// Paramètres :
// - body : le contenu du message Datum reçu
// - conn : connexion UDP (non utilisé ici mais peut être utile)
// - addr : adresse du peer ayant envoyé la donnée
//
// Fonctionnement :
// 1. Récupère le "node" en supprimant le hash initial.
// 2. Détermine le type de donnée (chunk, directory, big, bigDirectory).
// 3. Stocke le node dans le clientStorage.
// 4. Si c’est un chunk → rien de plus à faire.
// 5. Si c’est un directory → pour chaque entrée, ajoute un job dans DatumQueue pour récupérer le hash.
// 6. Si c’est un "big" ou "bigDirectory" → idem, ajoute les hash des sous-données dans DatumQueue.
func HandlefileDataWindow(body []byte, conn *net.UDPConn, addr *net.UDPAddr) {
	node := body[clientStorage.HashSize:]    // supprimer le hash en tête
	nodeType := clientStorage.Typedata(node) // déterminer le type

	clientStorage.FillMap(node) // stocker le node

	if nodeType == clientStorage.Chunk {
		return // chunk = pas d'autres hash à demander
	}

	switch nodeType {
	case clientStorage.Directory:
		// pour chaque entrée de directory, ajouter un job pour récupérer le hash
		for i := 0; i < len(node[clientStorage.IdSize:])/clientStorage.DirEntrySize; i++ {
			hash := node[clientStorage.IdSize+i*clientStorage.DirEntrySize+clientStorage.NameSize : clientStorage.IdSize+i*clientStorage.DirEntrySize+clientStorage.DirEntrySize]
			DatumQueue <- DatumJob{Hash: hash, Addr: addr}
		}

	case clientStorage.Big, clientStorage.BigDirectory:
		// pour chaque sous-hash, ajouter un job pour le récupérer
		for i := 0; i < len(node[clientStorage.IdSize:])/clientStorage.HashSize; i++ {
			hash := node[clientStorage.IdSize+i*clientStorage.HashSize : clientStorage.IdSize+i*clientStorage.HashSize+clientStorage.HashSize]
			DatumQueue <- DatumJob{Hash: hash, Addr: addr}
		}
	}
	if debugSlidingWindow {
		fmt.Println("Handle file data window terminé")
	}
}

// --------------------------------------------
// HandleDatumRequest
// --------------------------------------------
// Répond à un DatumRequest reçu d’un peer.
//
// Paramètres :
// - conn : connexion UDP
// - priv : clé privée du client (pour signer ou chiffrer si nécessaire)
// - addr : adresse du peer ayant envoyé la requête
// - id : ID de la requête (pour répondre correctement)
// - body : corps de la requête (contient le hash demandé)
//
// Fonctionnement :
// 1. Récupère le hash demandé.
// 2. Cherche la donnée correspondante dans le clientStorage.
// 3. Si trouvée :
//   - recalcul du hash pour vérifier l'intégrité
//   - chiffrement AES si le peer utilise le chiffrement
//   - envoi du message Datum avec hash + valeur
//
// 4. Sinon : envoi d’un NoDatum contenant juste le hash.
func HandleDatumRequest(conn *net.UDPConn, priv *ecdsa.PrivateKey, addr *net.UDPAddr, id uint32, body []byte) {
	hash := body[:clientStorage.HashSize]
	data, found := clientStorage.FindHash(hash)

	if found {
		if debugDatum {
			fmt.Println("DatumRequest: found data for hash", hex.EncodeToString(hash))
		}
		value := data
		hash := clientStorage.Sha(value)
		body := append(hash, value...)
		// chiffrement AES si nécessaire
		peer, exist := FindPeerByAddr(addr)
		if !exist {
			if debugDatum {
				fmt.Println("Le Peer n'existe pas")
			}
			return
		}
		if peer.SharedKey != nil {
			if debugCrypto {
				fmt.Println(" ici je chiffre les datum request")
				fmt.Printf("Key encrypt: %x\n", peer.SharedKey)
			}

			body_encrypted, err := encryptAESGCM(peer.SharedKey, body)
			if err != nil {
				fmt.Println("Erreur encrypt AES")
				return
			}
			sendGenericMessage(conn, priv, addr, id, Datum, body_encrypted, false)
			return

		}
		sendGenericMessage(conn, priv, addr, id, Datum, body, false)
		return
	} else {
		if debugDatum {
			fmt.Println("DatumRequest: no data for hash", hex.EncodeToString(hash))
		}
		sendGenericMessage(conn, priv, addr, id, NoDatum, hash, true)
		return
	}
}

//
// ======================= VÉRIFICATION DES ROOTS =======================
//

// CheckRoots parcourt tous les peers connus et envoie une requête RootRequest
// pour obtenir le Merkle Root actuel de chaque peer toutes les 30 secondes
// (Elle est commenté dans main.go)
func CheckRoots(conn *net.UDPConn, priv *ecdsa.PrivateKey) {
	ticker := time.NewTicker(3 * time.Minute) // déclenchement toutes les 30s

	for range ticker.C {
		for _, peer := range Peers {
			// Ignorer si pas connecté ou pas d'adresse active
			peer.Mupeer.RLock()
			if peer.State != PeerAssociated || peer.ActiveAddr == nil {
				continue
			}

			// Ignorer si le peer n’a pas encore de root connu
			if peer.Root == nil {
				continue
			}
			peer.Mupeer.RUnlock()
			// Ignorer les peers bannis
			if IsBan(peer.Name) {
				if debugDatum {
					fmt.Println("le peer est ban ! on lui delande pas son hashroot")
				}
				continue
			}

			// Générer un ID unique pour la transaction
			id := GenerateId()

			// Construire le message RootRequest
			msg, err := BuildMessage(id, RootRequest, []byte{}, priv, false)
			if err != nil {
				fmt.Println("Erreur ROOT pour " + peer.Name)
				continue
			}

			// Créer la transaction pour gérer la réponse
			CreateTransaction(id, peer, peer.ActiveAddr, RootRequest, msg, Retries)

			// Envoyer la requête RootRequest
			SendMessage(conn, peer.ActiveAddr, msg)
		}
	}
}
