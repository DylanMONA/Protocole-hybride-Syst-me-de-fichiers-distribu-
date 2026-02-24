package client

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"myp2p/clientStorage"
	"net"
	"sync/atomic"
	"time"
)

var debug = true

//
// ======================= TYPES DE MESSAGES =======================
//

// Constantes représentant les types de messages UDP échangés
const (
	// ---------- Requêtes ----------
	Ping                 uint8 = 0
	Hello                uint8 = 1
	RootRequest          uint8 = 2
	DatumRequest         uint8 = 3
	NatTraversalRequest  uint8 = 4
	NatTraversalRequest2 uint8 = 5
	// … autres types de requêtes possibles

	// ---------- Réponses ----------
	Ok         uint8 = 128
	Error      uint8 = 129
	HelloReply uint8 = 130
	RootReply  uint8 = 131
	Datum      uint8 = 132
	NoDatum    uint8 = 133
)

//
// ======================= FONCTIONS UTILITAIRES =======================
//

var globalId uint32 = 0

func GenerateId() uint32 {
	// incrémente atomiquement et retourne la nouvelle valeur
	return atomic.AddUint32(&globalId, 1) - 1
}

//
// ======================= CONSTRUCTION DES MESSAGES =======================
//

// BuildMessage construit un message UDP complet (ID + type + longueur + body + signature optionnelle)
// Paramètres :
//   - id    : identifiant unique de la transaction
//   - types : type du message
//   - body  : corps du message
//   - priv  : clé privée pour signer (nil si pas de signature)
//   - sign  : booléen pour indiquer si on signe le message

func BuildMessage(id uint32, types uint8, body []byte, priv *ecdsa.PrivateKey, sign bool) ([]byte, error) {
	buf := new(bytes.Buffer)

	// ID (4 octets)
	binary.Write(buf, binary.BigEndian, id)

	// Type (1 octet)
	buf.WriteByte(types)

	// Longueur du body (2 octets)
	binary.Write(buf, binary.BigEndian, uint16(len(body)))

	// Corps du message
	buf.Write(body)

	// Signature optionnelle
	if sign {
		signPart := buf.Bytes()
		sig, err := SignMessage(priv, signPart)
		if err != nil {
			if debug {
				fmt.Println("Erreur de signature")
			}
			return nil, err
		}
		// Ajouter la signature à la fin
		if _, err := buf.Write(sig); err != nil {
			if debug {
				fmt.Println("erreur d'écriture ")
			}
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// BuildHello construit un message Hello ou HelloReply
// Paramètres :
//   - id         : identifiant unique
//   - extensions : informations supplémentaires
//   - name       : nom du peer
//   - priv       : clé privée pour signer
//   - reply      : type du message (Hello ou HelloReply)

func BuildHello(id uint32, extensions uint32, name string, priv *ecdsa.PrivateKey, reply uint8) ([]byte, error) {
	// Construire le body : extensions (4 octets) + nom du peer
	body := make([]byte, ExtensionField+len(name))

	// Extensions
	body[0] = byte(extensions >> 24)
	body[1] = byte(extensions >> 16)
	body[2] = byte(extensions >> 8)
	body[3] = byte(extensions)

	// Nom du peer
	copy(body[ExtensionField:], []byte(name))

	// Utiliser BuildMessage pour créer le message complet avec signature
	msg, err := BuildMessage(id, byte(reply), body, priv, true)
	if err != nil {
		if reply == Hello {
			if debug {
				fmt.Println("fail build Hello :", err, reply)
			}
		}
		if reply == HelloReply {
			if debug {
				fmt.Println("fail build HelloReply :", err, reply)
			}
		}
		return nil, err
	}

	return msg, nil
}

// BuildHelloDH construit un Hello/HelloReply avec clé Diffie-Hellman
func BuildHelloDH(id uint32, extensions uint32, name string, dh_pub []byte, priv *ecdsa.PrivateKey, reply uint8) ([]byte, error) {
	if debug {
		fmt.Println("BuildHelloDH")
	}
	body := make([]byte, ExtensionField+len(name)+len(dh_pub))

	// Extensions
	body[0] = byte(extensions >> 24)
	body[1] = byte(extensions >> 16)
	body[2] = byte(extensions >> 8)
	body[3] = byte(extensions)

	// Nom du peer
	copy(body[ExtensionField:], []byte(name))
	body = append(body, dh_pub...)

	// Utiliser BuildMessage pour créer le message complet avec signature
	msg, err := BuildMessage(id, byte(reply), body, priv, true)
	if err != nil {
		if reply == Hello {
			if debug {
				fmt.Println("fail build Hello :", err, reply)
			}
		}
		if reply == HelloReply {
			if debug {
				fmt.Println("fail build HelloReply :", err, reply)
			}
		}
		return nil, err
	}

	return msg, nil

}

// BuildDatumRequest construit une requête de donnée pour un hash donné
func BuildDatumRequest(id uint32, hash []byte) ([]byte, error) {
	// Construire le body : hash (32 octets)
	body := make([]byte, clientStorage.HashSize)
	// hash
	copy(body, hash)

	// Utiliser BuildMessage pour créer le message complet avec signature
	msg, err := BuildMessage(id, byte(DatumRequest), body, nil, false)
	if err != nil {
		if debug {
			fmt.Println("fail build DatumRequest :", err)
		}
		return nil, err
	}

	return msg, nil

}

// BuildNatTraversalRequest construit une requête NAT Traversal
func BuildNatTraversalRequest(
	id uint32,
	priv *ecdsa.PrivateKey,
	addr *net.UDPAddr,
	msgType uint8,
) ([]byte, error) {

	buf := new(bytes.Buffer)

	if ip4 := addr.IP.To4(); ip4 != nil {
		buf.Write(ip4)
		binary.Write(buf, binary.BigEndian, uint16(addr.Port))
	} else {
		buf.Write(addr.IP.To16())
		binary.Write(buf, binary.BigEndian, uint16(addr.Port))
	}

	return BuildMessage(id, msgType, buf.Bytes(), priv, true)
}

//
// ======================= ENVOI DES MESSAGES =======================
//

// SendMessage envoie un message UDP à un peer et affiche les infos
func SendMessage(conn *net.UDPConn, addr *net.UDPAddr, msg []byte) error {
	n, err := conn.WriteToUDP(msg, addr)

	id, msgType, _, body, _, _, ok := parseRecvMessage(msg)

	if ok {
		if debug {
			fmt.Printf("→ Envoyé type=%d id=%d à %s\n %s,  nombre d'octets écrits  n : %d ", msgType, id, addr.String(), string(body), n)
		}
	}
	if debug {
		fmt.Println(" nombre d'octets écrits  n : ", n)
	}
	return err
}

// SendOk envoie une réponse OK
func SendOk(conn *net.UDPConn, id uint32, priv *ecdsa.PrivateKey, addr *net.UDPAddr) error {
	msg, err := BuildMessage(id, Ok, []byte{}, priv, false)
	if err != nil {
		if debug {
			fmt.Println("Erreur BuildMessage dans SendOk")
		}
		return err
	}
	return SendMessage(conn, addr, msg)
}

// SendErrorMessage envoie un message d'erreur avec texte
func SendErrorMessage(conn *net.UDPConn, id uint32, priv *ecdsa.PrivateKey, addr *net.UDPAddr, msg string) error {
	body := []byte(msg)

	pkt, err := BuildMessage(id, Error, body, priv, false)
	if err != nil {
		if debug {
			fmt.Println("Erreur BuildMessage dans SendErrorMessage")
		}
		return err
	}
	return SendMessage(conn, addr, pkt)
}

// SendError envoie une erreur générique sans body
func SendError(conn *net.UDPConn, id uint32, priv *ecdsa.PrivateKey, addr *net.UDPAddr) error {

	msg, err := BuildMessage(id, Error, []byte{}, priv, false)
	if err != nil {
		fmt.Println("Erreur BuildMessage dans SendOk")
		return err
	}
	return SendMessage(conn, addr, msg)
}

// sendGenericMessage envoie un message UDP générique (option sign)
func sendGenericMessage(conn *net.UDPConn, priv *ecdsa.PrivateKey, addr *net.UDPAddr, id uint32, msgType uint8, body []byte, sign bool) {
	msg, err := BuildMessage(id, msgType, body, priv, sign)
	if err != nil {
		if debug {
			fmt.Printf("Erreur BuildMessage type=%d: %v\n", msgType, err)
		}
		return
	}
	SendMessage(conn, addr, msg)
}

//
// ======================= NAT TRAVERSAL =======================
//

// Essaie de traverser un NAT pour un peer donné avec mécanisme de changement d'adresse en cas d'échec
func TryNatTraversal(conn *net.UDPConn, priv *ecdsa.PrivateKey, peer *Peer) bool {
	if debug {
		fmt.Println("On essaye le NatTraversal : " + peer.Name)
	}
	if peer.Name == NameofServeurUDP {
		return false
	}

	if peer.AddrIndex == -1 {
		peer.AddrIndex = 0
		fmt.Println("pas de changement d'addresse")
		return false
	}

	// si on a initié le tryNatTraversal alors le peer existe déjà avec une liste d'adresse

	// si j'ai envoyé un NatTraversal la 1er fois AddrIndex était au max

	// récupérer la prochaine adresse
	if _, err := peer.NextAddress(); err == false {
		return false
	}
	// on construit le message
	id := GenerateId()

	msg, err := BuildNatTraversalRequest(id, priv, peer.ActiveAddr, NatTraversalRequest)
	if err != nil {

		fmt.Println("erreur lors de la construction du NatTraversal dans TryNatTraversal ")

		return false
	}

	// on envoie le message
	server_addr, err := net.ResolveUDPAddr("udp", AddrServeurUDP)
	if err != nil {

		fmt.Printf("erreur lors de la transformation de l'adresse %s\n", server_addr)

		return false
	}
	fmt.Println("Construction et envoie d'un message NatTraversalRequest, id : ", id)
	// on crée une transaction

	CreateTransaction(id, peer, server_addr, NatTraversalRequest, msg, Retries-1)
	SendMessage(conn, server_addr, msg)

	return true

}

//
// ======================= HELLO PEER =======================
//

// Essaie de se connecter à un peer via Hello avec mécanisme de changement d'adresse
func HelloToPeer(conn *net.UDPConn, priv *ecdsa.PrivateKey, peer *Peer) bool {
	if debug {
		fmt.Println("Connection à un peer :" + peer.Name)
	}

	if debug {
		fmt.Printf("addrIndex : %d , len Addresses : %d \n", peer.AddrIndex, len(peer.Addresses))
	}
	if peer.AddrIndex == -1 {
		peer.AddrIndex = 0
		fmt.Println("pas de changement d'addresse")
		return false
	}

	// récupérer la prochaine adresse
	if _, err := peer.NextAddress(); err == false {
		return false
	}

	return SendHello(conn, priv, peer)
}

func SendHello(conn *net.UDPConn, priv *ecdsa.PrivateKey, peer *Peer) bool {

	fmt.Println("SendHello à un peer :" + peer.Name)
	if peer.PublicKey == nil {
		pub, err := GetPeerKey(peer.Name)
		if err != nil {
			if debug {
				fmt.Println("GetPeerKey failed:", err)
			}
			return false
		}
		peer.PublicKey = pub
	}

	// envoi du hello
	id := GenerateId()
	var msg []byte
	if chiffre == false || peer.Name == NameofServeurUDP {
		var err error
		ext := BuildExtension()
		if debugExtension {
			fmt.Printf("Voici l'extension Construite : 0x%08X\n", ext)
		}
		msg, err = BuildHello(id, ext, NameofOurPeer, priv, Hello)
		if err != nil {
			if debug {
				fmt.Println("erreur lors de la construction du helloRequest")
			}
			return false
		}

		CreateTransaction(id, peer, peer.ActiveAddr, Hello, msg, Retries-1)
	} else {
		dh_priv, dh_pub, err := GenerateKeyPair()
		if err != nil {
			return false
		}
		dh_pubByte := SerializePublicKey(dh_pub)
		if debug {
			fmt.Println("key pub genere(sendhello): ", hex.EncodeToString(dh_pubByte))
		}
		ext := BuildExtension()
		if debugExtension {
			fmt.Printf("Voici l'extension Construite (chiffré): 0x%08X\n", ext)
		}
		msg, err = BuildHelloDH(id, ext, NameofOurPeer, dh_pubByte, priv, Hello)
		if err != nil {
			if debug {
				fmt.Println("erreur lors de la construction du helloRequest")
			}
			return false
		}
		tx := &Transaction{
			Id:      id,
			Peer:    peer,
			Addr:    peer.ActiveAddr,
			MsgType: Hello,
			SentAt:  time.Now(),
			Timeout: 1 * time.Second,
			Retries: Retries - 1,
			Msg:     msg,
			State:   TxPending,
			DhPriv:  dh_priv,
		}
		addTransaction(tx)
	}
	if debug {
		fmt.Println("peer activeaddr : ", peer.ActiveAddr)
	}
	SendMessage(conn, peer.ActiveAddr, msg)

	return true
}
