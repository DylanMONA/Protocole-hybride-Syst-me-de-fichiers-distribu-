package UI

import (
	"crypto/ecdsa"
	"myp2p/client"
	"net"

	"fyne.io/fyne/v2/widget"
)

// -----------------------------
// BanSelectedPeers
// -----------------------------
// Ajoute les peers sélectionnés à la liste des bannis
// - Vérifie que la sélection n’est pas vide
// - Pour chaque peer sélectionné, ajoute le peer à la liste ban du client
// - Log l’action dans l’interface
func BanSelectedPeers(peerChecks *widget.CheckGroup, logger *Logger) {
	if len(peerChecks.Selected) == 0 {
		logger.Warn("Sélectionnez au moins un peer")
		return
	}
	for _, name := range peerChecks.Selected {
		peer, exist := client.FindPeer(name)
		if exist {
			client.AddBan(peer)
			logger.Info("→ ban  " + name)
		}
	}
}

// -----------------------------
// UnbanSelectedPeers
// -----------------------------
// Retire les peers sélectionnés de la liste des bannis
// - Vérifie que la sélection n’est pas vide
// - Pour chaque peer sélectionné, vérifie s’il est banni
// - Si oui, supprime le ban et log l’action
func UnbanSelectedPeers(peerChecks *widget.CheckGroup, logger *Logger) {
	if len(peerChecks.Selected) == 0 {
		logger.Warn("Sélectionnez au moins un peer")
		return
	}
	for _, name := range peerChecks.Selected {
		if client.IsBan(name) {
			client.DelBan(name)
			logger.Info("→ unban  " + name)
		}
	}
}

// -----------------------------
// HandshakeSelectedPeers
// -----------------------------
// Démarre un handshake (Hello) avec les peers sélectionnés
// - Vérifie que la sélection n’est pas vide
// - Pour chaque peer, vérifie qu’il existe et n’est pas déjà connecté
// - Lance le handshake en goroutine pour ne pas bloquer l’UI
func HandshakeSelectedPeers(peerChecks *widget.CheckGroup, conn *net.UDPConn, priv *ecdsa.PrivateKey, logger *Logger) {
	if len(peerChecks.Selected) == 0 {
		logger.Warn("Sélectionnez au moins un peer")
		return
	}
	for _, name := range peerChecks.Selected {
		peer, ok := client.FindPeer(name)
		if !ok {
			logger.Error("Peer introuvable ou invalide")
			continue
		}
		//----- à décommenter si vous voulez qu'un peer connecté ne peut plus refaire de handshake ------
		//if peer.State == client.PeerAssociated {
		//	logger.Warn("Déjà connecté : " + name)
		//	continue
		//}
		logger.Info("→ Handshake avec " + name)
		peer.AddrIndex = 0
		go client.HelloToPeer(conn, priv, peer) // handshake non bloquant
	}
}

// -----------------------------
// HandshakeAllPeers
// -----------------------------
// Démarre un handshake avec tous les peers connus mais non connectés
// - Parcourt tous les peers du client
// - Ignore les peers déjà connectés
// - Lance le handshake pour chaque peer non connecté
// - Log un avertissement si aucun peer n’est à connecter
func HandshakeAllPeers(conn *net.UDPConn, priv *ecdsa.PrivateKey, logger *Logger) {
	count := 0
	for name, peer := range client.Peers {
		if peer.State == client.PeerAssociated {
			continue
		}
		count++
		logger.Info("→ Handshake avec " + name)
		go client.HelloToPeer(conn, priv, peer) // handshake en goroutine
	}
	if count == 0 {
		logger.Warn("Aucun peer non connecté")
	}
}
