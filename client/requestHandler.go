package client

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"myp2p/clientStorage"
	"net"
)

//
// ======================= CHANNEL DE REQUÊTES =======================
//

// Canal pour recevoir toutes les requêtes entrantes
var requestChan = make(chan IncomingPacket, 1024)
var debugRequest = true

//
// ======================= LOOP DE TRAITEMENT DES REQUÊTES =======================
//

// RequestHandler lit le canal et dispatch les requêtes selon leur type
func RequestHandler(conn *net.UDPConn, priv *ecdsa.PrivateKey) {
	for {
		msg := <-requestChan
		pkt := msg.pkt
		addr := msg.addr

		// On parse le message
		id, typ, bodyLen, body, signed, sig, ok := parseRecvMessage(pkt)
		if !ok {
			if debugRequest {
				fmt.Println("Request parse error")
			}
			continue
		}

		if debugRequest {
			fmt.Printf("RequestHandler: reçu type=%d id=%d body=%s\n", typ, id, string(body))
		}

		// dispatch vers la fonction spécifique
		switch typ {
		case NatTraversalRequest:
			HandleNatTraversalRequest(conn, priv, id, body, bodyLen, addr, signed, sig)

		case NatTraversalRequest2:
			HandleNatTraversalRequest2(conn, priv, id, body, bodyLen, addr, signed, sig)

		case Hello:
			HandleHelloRequest(conn, priv, addr, id, body, signed, sig)
		case RootRequest:
			HandleRootRequest(conn, priv, id, addr)

		case Ping:
			HandlePing(conn, priv, id, addr)

		case DatumRequest:
			HandleDatumRequestWrapper(conn, priv, id, addr, body)

		default:
			if debugRequest {
				fmt.Printf("Requête inconnue type=%d\n", typ)
			}
			SendError(conn, id, priv, addr)
		}

		updateLastSeen(addr)
	}
}

// ----------------------
// Fonctions auxiliaires
// ----------------------

// NatTraversalRequest : premier message pour initier traversée NAT
func HandleNatTraversalRequest(conn *net.UDPConn, priv *ecdsa.PrivateKey, id uint32, body []byte, bodyLen int, addr *net.UDPAddr, signed []byte, sig []byte) {
	if debugRequest {
		fmt.Println("-> NatTraversalRequest Reçu !")
	}

	// On vérifie la signature
	if !VerifSign(addr, signed, sig) {
		if debugRequest {
			fmt.Println("Erreur de signature dans NatTraversalRequest")
		}
		return
	}
	// On envoie Ok à celui qui a fait la requete
	SendOk(conn, id, priv, addr)

	// On exxtrait l'adresse de celui avec qu'il veut discuter
	addrExtracted, err := ParseNATBody(body, uint8(bodyLen))
	if err != nil {
		fmt.Println("Erreur ParseNATBody")
		return
	}

	// on construit un NatTraversalRequest2
	newID := GenerateId()
	msg, err := BuildNatTraversalRequest(newID, priv, addr, NatTraversalRequest2)
	if err != nil {
		fmt.Println("Erreur de construction NatTraversalRequest2")
		return
	}
	// on crée une transaction et on l'envoie
	CreateTransaction(newID, nil, addrExtracted, NatTraversalRequest2, msg, Retries)
	SendMessage(conn, addrExtracted, msg)
}

// NatTraversalRequest2 : réponse pour compléter traversée NAT
func HandleNatTraversalRequest2(conn *net.UDPConn, priv *ecdsa.PrivateKey, id uint32, body []byte, bodyLen int, addr *net.UDPAddr, signed []byte, sig []byte) {
	if debugRequest {
		fmt.Println("-> NatTraversalRequest2 Reçu !")
	}

	// On extrait le nom
	addrExtracted, err := ParseNATBody(body, uint8(bodyLen))
	if err != nil {
		fmt.Println("Erreur ParseNATBody")
		return
	}

	// On rafraichit la liste par prudence
	names, err := GetPeerList()
	if err != nil {
		fmt.Println("Peer List Error in NatTraversalRequest2")
		return
	}
	RefreshPeers(names)

	// On retrouve le peer pour pouvoir lui ajouter sa clé public
	peer, exist := FindPeerByAddr(addrExtracted)
	if !exist {
		if debugRequest {
			fmt.Println("NatTraversalRequest2 ignoré, peer inconnu")
		}
		return
	}
	if OnPeerEvent != nil {
		OnPeerEvent(peer, EventNatTraversal2Received, "")
	}
	peer.ActiveAddr = addrExtracted

	key, err := GetPeerKey(peer.Name)
	if err != nil {
		fmt.Println("Erreur récupération clé publique dans NatTraversal2")
		return
	}
	peer.PublicKey = key

	if !VerifSign(addr, signed, sig) {
		if debugRequest {
			fmt.Println("Erreur de signature dans NatTraversalRequest2")
		}
		return
	}

	SendOk(conn, id, priv, addr)

	newID := GenerateId()

	sendGenericMessage(conn, priv, addrExtracted, newID, Ping, []byte{}, false)
}

// RootRequest : renvoie la racine Merkle si autorisé
func HandleRootRequest(conn *net.UDPConn, priv *ecdsa.PrivateKey, id uint32, addr *net.UDPAddr) {
	if debugRequest {
		fmt.Println("-> RootRequest reçu")
	}
	if IsBanByaddr(addr) {
		SendErrorMessage(conn, id, priv, addr, "Tu es banni.")
	} else {
		sendGenericMessage(conn, priv, addr, id, RootReply, clientStorage.RootHash, true)
	}
}

// Ping : simple vérification de présence
func HandlePing(conn *net.UDPConn, priv *ecdsa.PrivateKey, id uint32, addr *net.UDPAddr) {
	if debugRequest {
		fmt.Println("-> Ping reçu")
	}
	// je cherche le peer correspondant à l'addresse
	peer, ok := FindPeerByAddr(addr)
	if !ok {
		fmt.Println("peer not found")
		SendErrorMessage(conn, id, priv, addr, "Please Hello First ! ;)")
		return
	}
	peer.Mupeer.RLock()
	state := peer.State
	peer.Mupeer.RUnlock()

	// si le peer attendait un ping pour son nat
	if state == PeerWaitHelloNat {
		peer.Mupeer.Lock()
		// je le note comme pret à faire le hello
		peer.State = PeerDiscovered
		peer.Mupeer.Unlock()

		NoChangeAddr(peer, addr)
		// j'envoie Hello
		SendHello(conn, priv, peer)

	} else {
		if state == PeerDiscovered || state == PeerExpired {
			SendErrorMessage(conn, id, priv, addr, "Please Hello First ! ;)")
			return
		}
	}
	// dans tous les cas j'envoie ok
	sendGenericMessage(conn, priv, addr, id, Ok, []byte{}, false)
}

// DatumRequest : wrapper pour vérifier bannissement avant traitement
func HandleDatumRequestWrapper(conn *net.UDPConn, priv *ecdsa.PrivateKey, id uint32, addr *net.UDPAddr, body []byte) {
	if debugRequest {
		fmt.Println("-> DatumRequest reçu")
	}
	if IsBanByaddr(addr) {
		SendErrorMessage(conn, id, priv, addr, "Tu es banni.")
		return
	}
	HandleDatumRequest(conn, priv, addr, id, body)
}

// HelloRequest : traitement d’un Hello reçu
func HandleHelloRequest(conn *net.UDPConn, priv *ecdsa.PrivateKey, addr *net.UDPAddr, id uint32, body []byte, signed []byte, sig []byte) {
	if debugRequest {
		fmt.Println("-> Hello reçu")
	}
	if !VerifSign(addr, signed, sig) {
		if debugRequest {
			fmt.Println("Erreur de signature dans Hellorequest")
		}
		return
	}

	// Nous recevons hello et nous construisons le message helloreply
	var reply []byte
	var err error
	var sharesecret []byte

	// Créer un peer
	name, err := ExtractPeerName(body)
	if err != nil {
		fmt.Println("Impossible d'extraire le nom du peer:", err)
		return
	}

	if debugExtension {
		ext, err := ParseExtensions(body)
		if err != nil {
			fmt.Println("Erreur aucun champs extension trouvé")
		}
		fmt.Printf("Voici l'extension du Hello reçu : 0x%08X\n", ext)
	}

	ext := BuildExtension()
	crypted := IsChiffrementEnabled(body)
	// Si le message est n'est pas chiffré
	if !crypted {
		if debugExtension {
			fmt.Println("Hello Request : Message non chiffré")
		}

		if debugExtension {
			fmt.Printf("Voici l'extension Construite quand je reçois un Hello et j'envoie HelloReply: 0x%08X\n", ext)
		}

		reply, err = BuildHello(id, ext, NameofOurPeer, priv, HelloReply)
		if err != nil {
			fmt.Println("erreur lors de la construction du helloReply")
			return
		}
	} else {
		if debugExtension {
			fmt.Println("Hello Request : Message chiffré")
		}
		// Si le message n'est pas chiffré
		dh_priv, dh_pub, err := GenerateKeyPair()
		if err != nil {
			fmt.Println("erreur génération de clé")
			return
		}
		dh_pubByte := SerializePublicKey(dh_pub)

		reply, err = BuildHelloDH(id, ext, NameofOurPeer, dh_pubByte, priv, HelloReply)
		if err != nil {
			fmt.Println("erreur lors de la construction du helloReply")
			return
		}

		dh_pubpeer, err := ParsePublicKey(body[len(body)-64:])
		if err != nil {
			fmt.Println("erreur lors de ParsePublicKey")
			return
		}
		sharesecret, err = ComputeSharedKey(dh_priv, dh_pubpeer)
		if debugRequest {
			fmt.Println("cle pub genere : ", hex.EncodeToString(dh_pubByte), "\n cle public recu : ", hex.EncodeToString(body[len(body)-64:]))
			fmt.Println("secret partager :", hex.EncodeToString(sharesecret))
		}
		if err != nil {
			fmt.Println("erreur lors du computesharekey")

			return
		}

	}

	// Construire et envoyer HelloReply signé

	key, err := GetPeerKey(name)
	if err != nil {
		fmt.Println("Probleme de clé dans request handler:", err)

		return
	}
	peer, exist := FindPeer(name)
	if !exist {
		fmt.Println("peer inconnu.")
		return
	}

	peer.Mupeer.RLock()
	state := peer.State
	peer.Mupeer.RUnlock()

	if state == PeerAssociated {
		// si le peer a deja fait helloreply mais ya eu un autre hello apres
		// si le peer existe et est connecté alors je le laisse connecté
		AddPeer(name, addr, key, PeerAssociated)

	}
	// si le peer n'existe pas ou n'est pas connecté
	if peer != nil && state == PeerDiscovered {
		AddPeer(name, addr, key, PeerDiscovered)
	}
	if crypted || name != NameofServeurUDP {

		if !exist {
			if debugRequest {
				fmt.Println("Peer non connu")
			}
			return
		}
		peer.SharedKey = sharesecret
	}

	SendMessage(conn, addr, reply)

	// le deuxième cas au cas où au moment ou on entre dans la phase tenté le natTraversal à ce moment là on reçoit une réponse
	if state == PeerDiscovered || state == PeerWaitHelloNat {
		if debugRequest {
			fmt.Println("-> je veux savoir qui il est je lui envoie également hello (il est pas encore connecté)")
		}
		SetPeerAddrIndex(peer, peer.ActiveAddr)
		SendHello(conn, priv, peer)
	}
}
