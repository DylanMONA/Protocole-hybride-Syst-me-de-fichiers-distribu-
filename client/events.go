package client

// PeerEventType définit le type d'événement pouvant survenir pour un peer.
// C'est une simple chaîne de caractères (string) pour identifier facilement l'événement.
type PeerEventType string

// Définition des différents événements possibles liés à un peer.
const (
	EventConnected              PeerEventType = "Connected"              // Un peer vient de se connecter avec succès.
	EventConnectionFailed       PeerEventType = "ConnectionFailed"       // La tentative de connexion au peer a échoué.
	EventNewRoot                PeerEventType = "NewRoot"                // Le peer a publié un nouveau Merkle Root.
	EventMerkleDownloadComplete PeerEventType = "MerkleDownloadComplete" // Téléchargement complet de l'arbre de Merkle depuis ce peer.
	EventNoDatum                PeerEventType = "NoDatum"                // Le peer n'a pas de donnée demandée (Datum manquant).
	EventNatTraversal2Received  PeerEventType = "NatTraversal2Received"  // Réception d'une réponse NAT Traversal de type 2.
	EventDisconnected           PeerEventType = "Deconnected"            // peer déconnecté
	EventMerkleDownloadLocal    PeerEventType = "MerkleDownloadLocal"    // téléchargement depuis ce qu'on possède déjà
)

// OnPeerEvent est un callback global optionnel qui peut être défini par le client.
// Il est appelé à chaque événement important concernant un peer.
// Paramètres :
// - peer : le peer concerné
// - event : le type d'événement (PeerEventType)
// - details : informations supplémentaires ou message associé à l'événement
var OnPeerEvent func(peer *Peer, event PeerEventType, details string)
