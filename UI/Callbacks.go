package UI

import "myp2p/client"

// --------------------------------------------
// RegisterCallbacks
// --------------------------------------------
// Fonction qui enregistre les callbacks pour les événements des peers.
// Ces callbacks permettent à l'interface utilisateur (ou au logger)
// de réagir automatiquement lorsque certains événements se produisent.
//
// Paramètre :
// - log : instance de Logger pour afficher des messages d'information, d'avertissement ou d'erreur.
func RegisterCallbacks(log *Logger) {

	// On assigne une fonction anonyme à client.OnPeerEvent
	client.OnPeerEvent = func(peer *client.Peer, event client.PeerEventType, details string) {
		switch event {

		// -----------------------------
		// Connexion réussie
		// -----------------------------
		case client.EventConnected:
			log.Info("Peer connecté : " + peer.Name)

		// -----------------------------
		// Échec de connexion
		// -----------------------------
		case client.EventConnectionFailed:
			log.Error("Impossible de connecter le peer " + peer.Name + " : " + details)

		// -----------------------------
		// Donnée demandée non disponible
		// -----------------------------
		case client.EventNoDatum:
			log.Warn("NoDatum reçu pour le peer " + peer.Name + " " + details)

		// -----------------------------
		// Nouveau root reçu
		// -----------------------------
		case client.EventNewRoot:
			log.Info("Nouveau ROOT de " + peer.Name + " : " + details)

		// -----------------------------
		// Téléchargement complet de l'arbre Merkle
		// -----------------------------
		case client.EventMerkleDownloadComplete:
			log.Info("Merkle téléchargé depuis " + peer.Name + " : " + details)

		// -----------------------------
		// Réception d'une requête NAT Traversal de type 2
		// -----------------------------
		case client.EventNatTraversal2Received:
			log.Info("NatTraversalRequest2 reçu pour le peer " + peer.Name)

		// -----------------------------
		// Timeout : Peer déconnecté
		// -----------------------------
		case client.EventDisconnected:
			log.Warn("Le peer " + peer.Name + " est déconnecté.")

		// -----------------------------
		// Les données sont pas demandés car on les possède déjà
		// -----------------------------
		case client.EventMerkleDownloadLocal:
			log.Info("Merkle téléchargé depuis le système " + details)
		}

	}
}
