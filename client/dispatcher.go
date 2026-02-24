package client

import (
	"crypto/ecdsa"
	"fmt"
	"net"
)

// HandshaWithServer indique si un handshake avec le serveur est nécessaire.
// True par défaut : on doit effectuer un handshake initial avant de considérer le peer comme pleinement connecté.
var HandshaWithServer = true
var debugDispatcher = false

// IncomingPacket représente un paquet reçu d’un peer.
// Il contient :
// - pkt  : le contenu brut du message UDP
// - addr : l'adresse UDP de l'expéditeur
type IncomingPacket struct {
	pkt  []byte
	addr *net.UDPAddr
}

// ------------------- CaptureMessage ------------------------------------
// CaptureMessage lit en boucle tous les messages UDP reçus sur la connexion.
//
// Paramètres :
// - conn : connexion UDP sur laquelle écouter
// - priv : clé privée du client (pour éventuellement vérifier ou déchiffrer les messages)
//
// Fonctionnement :
// 1. Crée un buffer large (65535 octets) pour lire n’importe quel paquet UDP.
// 2. Lit un paquet UDP.
// 3. Copie le contenu reçu pour éviter que le buffer soit écrasé lors du prochain Read.
// 4. Redirige le paquet vers le routeur pour savoir s’il s’agit d’une requête ou d’une réponse.
func CaptureMessage(conn *net.UDPConn, priv *ecdsa.PrivateKey) {
	buf := make([]byte, 65535) // buffer large pour recevoir tout type de paquet

	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err == nil && n > 0 {
			// copier le paquet reçu pour ne pas écraser le buffer
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			// dispatcher le paquet selon son type
			Routeur(pkt, raddr, conn, priv)
		}
	}
}

// ------------------- Routeur ------------------------------------
// Routeur analyse un paquet reçu et le redistribue vers le canal approprié.
//
// Paramètres :
// - pkt  : le paquet reçu
// - addr : adresse UDP de l’expéditeur
// - conn : connexion UDP (utile si certaines fonctions veulent renvoyer une réponse)
// - priv : clé privée (utile si signature/déchiffrement)
//
// Fonctionnement :
// 1. Vérifie que le paquet est suffisamment long (>=7 octets) pour contenir ID, type et longueur.
// 2. Parse le paquet avec parseRecvMessage (extrait type, corps, signature, etc.).
// 3. Si le type du message > 127 → c’est une réponse, on le met dans responseChan.
// 4. Sinon → c’est une requête, on le met dans requestChan.
func Routeur(pkt []byte, addr *net.UDPAddr, conn *net.UDPConn, priv *ecdsa.PrivateKey) {
	if len(pkt) < 7 {
		if debugDispatcher {
			fmt.Println("Paquet trop court, ignoré")
		}
		return
	}

	_, typ, _, _, _, _, ok := parseRecvMessage(pkt)
	if !ok {
		fmt.Println("erreur lors du parseRecvMessage")
		return
	}

	// typ > 127 = réponse, typ <= 127 = requête
	if typ > 127 {
		if debugDispatcher {
			fmt.Println("Dispatcher: réponse → responseChan")
		}
		responseChan <- IncomingPacket{pkt: pkt, addr: addr}
	} else {
		if debugDispatcher {
			fmt.Println("Dispatcher: requête  → requestChan")
		}
		requestChan <- IncomingPacket{pkt: pkt, addr: addr}
	}
}
