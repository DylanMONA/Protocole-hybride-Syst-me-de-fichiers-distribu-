package client

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"myp2p/clientStorage"
	"net"
	"time"
)

//
// ======================= CHANNEL DE RÉCEPTION =======================
//

// Canal pour recevoir tous les paquets entrants
var responseChan = make(chan IncomingPacket, 1024)
var debugResponse = true

//
// ======================= LOOP DE TRAITEMENT DES RÉPONSES =======================
//

// ResponseHandler traite toutes les réponses reçues sur le canal
func ResponseHandler(conn *net.UDPConn, priv *ecdsa.PrivateKey) {
	for msg := range responseChan {
		pkt := msg.pkt
		addr := msg.addr

		// On parse le message
		id, typ, bodyLen, body, signed, sig, ok := parseRecvMessage(pkt)
		if !ok {
			if debugResponse {
				fmt.Println("Response parse error")
			}
			continue
		}
		if debugResponse {
			fmt.Printf("ResponseHandler: reçu type=%d id=%d bodyLen=%d\n", typ, id, bodyLen)
		}
		// On cherche le type de message pour le rediriger vers le bon handler
		switch typ {
		case HelloReply:
			if debugExtension {
				ext, err := ParseExtensions(body)
				if err != nil {
					fmt.Println("Erreur aucun champs extension trouvé")
				}
				fmt.Printf("Voici l'extension du HelloReply reçu : 0x%08X\n", ext)
			}

			if err := HandleHelloReply(id, conn, priv, signed, sig); err != nil && debugResponse {
				fmt.Println("Erreur HelloReply :", err)
			}
		case RootReply:
			HandleRootReply(id, addr, signed, sig, body)
		case Ok:
			HandleOk(id, addr)
		case Error:
			resolveTransaction(id)
			fmt.Println("→ Error reçu, body :", string(body))

		case Datum:
			HandleDatum(id, addr, body)
		case NoDatum:
			HandleNoDatum(id, addr, signed, sig)
		default:
			if debugResponse {
				fmt.Printf("Réponse inconnue type=%d\n", typ)
			}

		}

		// Mise à jour du LastSeen du peer
		updateLastSeen(addr)
	}
}

//
// ======================= GESTION PAR TYPE DE MESSAGE =======================
//

// RootReply : ajout de la racine Merkle au peer
func HandleRootReply(id uint32, addr *net.UDPAddr, signed []byte, sig []byte, body []byte) {
	if debugResponse {
		fmt.Println("→ RootReply reçu")
	}
	tr, ok := resolveTransaction(id)
	if !ok || tr.MsgType != RootRequest {
		return
	}

	if !VerifSign(addr, signed, sig) {
		if debugResponse {
			fmt.Println("Erreur de signature dans RootReply")
		}
		return
	}

	AddRootToPeerbyaddr(addr, body)
}

// OK : confirmation reçue
func HandleOk(id uint32, addr *net.UDPAddr) {
	if debugResponse {
		fmt.Println("→ OK reçu")
	}
	tx, ok := resolveTransaction(id)
	if !ok {
		return
	}

	if tx.MsgType == NatTraversalRequest {
		peer := tx.Peer
		if debugResponse {
			fmt.Println("Ok reçu pour NatTraversalRequest, peer connecté ?", peer.State == PeerAssociated)
		}
	}
}

// Datum : données reçues d’un peer
func HandleDatum(id uint32, addr *net.UDPAddr, body []byte) {
	tr, ok := resolveTransaction(id)
	if !ok || tr.MsgType != DatumRequest {
		if debugResponse {
			fmt.Println("Différent de Datum request")
		}
		return
	}

	peer, exist := FindPeerByAddr(addr)
	if !exist {
		if debugResponse {
			fmt.Println("Peer non trouvé pour Datum")
		}
		return
	}
	// Calcul RTT
	rtt := time.Since(tr.SentAt)
	peer.Window.OnSuccess(rtt)

	DataBody := body
	// Déchiffrement si nécessaire
	if peer.SharedKey != nil {
		if len(body) < clientStorage.HashSize {
			if debugResponse {
				fmt.Println("Corps de message trop court pour déchiffrement")
			}
			return
		}
		cipher := body
		if debugCrypto {
			fmt.Println("ici on déchiffre les messages ")
			fmt.Printf("Key decrypt: %x\n", peer.SharedKey)
		}
		plaintext, err := decryptAESGCM(peer.SharedKey, cipher)
		if err != nil {
			fmt.Println("Erreur déchiffrement Datum :", err)
			return
		}
		DataBody = plaintext
	}

	body, len, ok := getBody(tr.Msg)
	if !ok {
		if debugResponse {
			fmt.Println("error body not find")
		}
		return
	}

	// Vérification de l’intégrité des données
	if VerifyDataIntegrity(DataBody, body[:len]) {
		if debugResponse {
			fmt.Println("Intégrité des données vérifiée")
		}
		HandlefileDataWindow(DataBody, nil, addr)

		if debugResponse {
			fmt.Println("Merkle Done : ", peer.MerkleDone)
			fmt.Println("clientStorage.VerifyMerkle(peer.Root)", clientStorage.VerifyMerkle(peer.Root))
		}
		if !peer.MerkleDone && clientStorage.VerifyMerkle(peer.Root) {
			peer.MerkleDone = true

			fmt.Println("-> ----  Téléchargement terminée ----")

			if !peer.MerkleDownloadStart.IsZero() && OnPeerEvent != nil {
				duration := time.Since(peer.MerkleDownloadStart)
				OnPeerEvent(peer, EventMerkleDownloadComplete, fmt.Sprintf("durée: %s", duration.Round(time.Millisecond)))
			}
		}
	} else {
		if debugResponse {
			fmt.Println("Intégrité des données échouée pour Datum")
		}
	}
}

// NoDatum : le peer n’a pas la donnée demandée
func HandleNoDatum(id uint32, addr *net.UDPAddr, signed []byte, sig []byte) {
	tr, ok := resolveTransaction(id)
	if !ok || tr.MsgType != DatumRequest {
		return
	}
	peer, exist := FindPeerByAddr(addr)
	if !exist {
		if debugResponse {
			fmt.Println("le peer n'existe pas Handle No Datum")
		}
		return
	}

	rtt := time.Since(tr.SentAt)
	peer.Window.OnSuccess(rtt)

	if !VerifSign(addr, signed, sig) {
		fmt.Println("Erreur de signature dans NoDatum")
	}

	if OnPeerEvent != nil {
		OnPeerEvent(peer, EventNoDatum, " :(")
	}
}

// HelloReply : traitement du retour Hello d’un peer
func HandleHelloReply(id uint32, conn *net.UDPConn, priv *ecdsa.PrivateKey, signed []byte, sig []byte) error {
	if debugResponse {
		fmt.Println("-> HandleHelloReply")
	}

	// 1. Vérifier si une transaction existe
	transaction, ok := resolveTransaction(id)
	if !ok {
		if debugResponse {
			fmt.Println("HelloReply ignoré : pas de transaction correspondante")
		}
		return nil
	}

	peer := transaction.Peer
	if peer == nil {
		if debugResponse {
			fmt.Println("transaction sans peer associé")
		}
		return fmt.Errorf("transaction sans peer associé")
	}

	// 2. Vérifier la signature du message
	okSign, err := VerifyMessage(peer.PublicKey, signed, sig)
	if err != nil {
		if debugResponse {
			fmt.Println("Erreur de verification de la signature :", err)
		}
		return err
	}
	if !okSign {
		OnPeerEvent(peer, EventConnectionFailed, "HelloReply Non Signé Correctement, on ignore le peer.")
		if debugResponse {
			fmt.Println("Paquet non signé correctement, rejet du peer")
		}
		return nil
	}

	if debugResponse {
		fmt.Println("Paquet vérifié conforme, on traite le peer")
	}

	// 1. Extraire le body de la transaction
	body, _, ok := getBody(transaction.Msg)
	if !ok {
		if debugResponse {
			fmt.Println("Erreur parsing body transaction")
		}
		return fmt.Errorf("Erreur parsing body transaction %d", transaction.Id)
	}

	// 3. Gérer le peer "simple" (pas de chiffrement DH)
	// On vérifie si le peer implémente l'extension de diffie hellman
	crypted := IsChiffrementEnabled(body)
	if debugResponse {
		if crypted == true {
			fmt.Println("crypted vaut true")
		}
	}
	if !crypted || peer.Name == NameofServeurUDP {
		if debugExtension {
			fmt.Println("-> Hello Reply: Message non chiffré")
		}
		return handlePlainHelloReply(transaction, peer, conn, priv)
	}
	if debugExtension {
		fmt.Println("-> Hello Reply : Message chiffré")
	}
	// 4. Gérer le peer chiffré / clé DHted :=
	return handleDHHelloReply(transaction, peer, signed, body, conn, priv)
}

// -----------------------------
// Gestion d'un HelloReply non chiffré
// -----------------------------
func handlePlainHelloReply(transaction *Transaction, peer *Peer, conn *net.UDPConn, priv *ecdsa.PrivateKey) error {
	if transaction.MsgType != Hello {
		if debugResponse {
			fmt.Println("Transaction non attendue pour HelloReply, on ignore")
		}
		return nil
	}

	if debugResponse {
		fmt.Println("Connection établie pour peer non chiffré !")
	}
	peer.Mupeer.RLock()
	state := peer.State
	peer.Mupeer.RUnlock()

	// on lance la maintenance
	if state == PeerDiscovered {
		if debugMaintenance {
			fmt.Println("-> Peer discovered on lance la maintenance")
		}
		go MaintenancePerPeer(conn, priv, peer)
	}
	// puis on le note comme connecté
	connectPeer(peer)

	return nil
}

// -----------------------------
// Gestion d'un HelloReply avec clé partagée DH
// -----------------------------
func handleDHHelloReply(transaction *Transaction, peer *Peer, signed []byte, body []byte, conn *net.UDPConn, priv *ecdsa.PrivateKey) error {

	// 2. Récupérer clé publique du peer depuis le message signé
	if len(signed) < 64 {
		if debugResponse {
			fmt.Println("message HelloReply trop court pour extraire clé publique")
		}
		return fmt.Errorf("message HelloReply trop court pour extraire clé publique")
	}
	dhPub, err := ParsePublicKey(signed[len(signed)-64:])
	if err != nil {
		fmt.Println("Erreur ParsePublicKey :", err)
		return err
	}

	// 3. Calculer la clé partagée
	sharedKey, err := ComputeSharedKey(transaction.DhPriv, dhPub)
	if err != nil {
		fmt.Println("Erreur calcul clé partagée :", err)
		return err
	}

	if debugResponse {
		fmt.Println("Clé publique reçue :", hex.EncodeToString(signed[len(signed)-64:]))
		fmt.Println("Clé publique body :", hex.EncodeToString(body[len(body)-64:]))
		fmt.Println("Secret partagé :", hex.EncodeToString(sharedKey))
	}

	// 4. Connecter le peer et stocker la clé partagée
	if transaction.MsgType == Hello {

		peer.SharedKey = sharedKey
		if debugResponse {
			fmt.Println("Connection établie et clé partagée générée !")
		}

		peer.Mupeer.RLock()
		state := peer.State
		peer.Mupeer.RUnlock()
		if state == PeerDiscovered {
			if debugMaintenance {
				fmt.Println("-> Peer discovered on lance la maintenance")
			}
			go MaintenancePerPeer(conn, priv, peer)
		}
		// on lance la maintenance puis on le note comme connecté
		connectPeer(peer)
	}

	return nil
}
