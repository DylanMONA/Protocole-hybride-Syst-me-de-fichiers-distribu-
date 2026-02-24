package client

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"net"
	"time"
)

var debugMaintenance = true

//
// ======================= MAINTENANCE PÉRIODIQUE =======================
//

// Maintenance : gère les pings réguliers et la déconnexion des peers inactifs
func MaintenancePerPeer(conn *net.UDPConn, priv *ecdsa.PrivateKey, peer *Peer) {

	PingInterval := 1 * time.Minute // fréquence d'envoi du ping
	timeout := 6 * time.Minute      // délai avant de déconnecter un peer inactif
	// --------------------------
	// Envoi des ping
	// --------------------------

	for {

		now := time.Now() // timestamp actuel

		if debugMaintenance {
			fmt.Println("-> Début de la maintenance, peer de nom :", peer.Name)
		}
		peer.Mupeer.RLock()
		addr := peer.ActiveAddr
		peer.Mupeer.RUnlock()

		id := GenerateId()
		// Envoyer le ping
		sendGenericMessage(conn, priv, addr, id, Ping, []byte{}, false)

		// Si pas de réponse depuis plus de timeout → déconnecter le peer
		if now.Sub(peer.LastSeen) >= timeout {
			if debug {
				fmt.Println("Maintenance: Timeout mark disconnected:", peer.Name)
			}
			DeconnectPeer(peer)
			return
		}

		time.Sleep(PingInterval)
	}

}

//
// ======================= BOUCLE DE MAINTENANCE =======================
//

// AliveHTTPS envoie périodiquement des messages au serveur pour rester actif
func KeepAlive(
	conn *net.UDPConn,
	priv *ecdsa.PrivateKey,
	pub *ecdsa.PublicKey,
	addrServeur *net.UDPAddr,
) {
	// on effectue le premier handshake avec le serveur
	time.Sleep(200 * time.Millisecond)
	// Handshake périodique
	if err := HandShakeWithServer(conn, priv, addrServeur); err != nil {
		if debugMaintenance {
			fmt.Println(" Erreur handshake périodique :", err)
		}
	}
	time.Sleep(200 * time.Millisecond)

	for {
		// on maintient la connexion toutes les 28min
		time.Sleep(20 * time.Minute)

		if debugMaintenance {
			fmt.Println(" KeepAlive / Handshake périodique")
		}

		pubBytes := SerializePublicKey(pub)
		if err := RegisterKey(NameofOurPeer, pubBytes); err != nil {
			log.Fatal("Erreur lors de l'enregistrement du peer :", err)
		}
		// Handshake périodique
		if err := HandShakeWithServer(conn, priv, addrServeur); err != nil {
			if debugMaintenance {
				fmt.Println(" Erreur handshake périodique :", err)
			}
		}

		if debugMaintenance {
			fmt.Println(" FINN KeepAlive / Handshake périodique")
		}
	}
}
