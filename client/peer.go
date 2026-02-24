package client

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"myp2p/clientStorage"
	"net"
	"sync"
	"time"
)

//
// ======================= VARIABLES GLOBALES =======================
//

// Mutex pour protéger l'accès concurrent aux maps
var (
	PeersMu sync.RWMutex
	Peers   = map[string]*Peer{} // Tous les peers connus
	ban     = map[string]*Peer{} // Liste des peers bannis
	banMu   sync.RWMutex
)

type PeerState int

const (
	PeerDiscovered   PeerState = iota // connu via le serveur
	PeerWaitHelloNat                  // pour dire "je suis en attente d'un ping j'ai initié la traversée de Nat"
	PeerAssociated                    // handshake OK
	PeerExpired                       // association expirée
)

// Liste de nos roots racine
var MyListroots [][]byte // nos 3 derniers roots choisi

//
// ======================= STRUCTURE D’UN PEER =======================
//

var debugPeer = true

// Peer représente un noeud connu dans le réseau
type Peer struct {
	Name                string       // Nom unique du peer
	Addresses           []string     // Toutes les adresses possibles (NAT traversal)
	AddrIndex           int          // Index de l’adresse en cours d’utilisation
	ActiveAddr          *net.UDPAddr // Adresse validée et utilisée
	PublicKey           *ecdsa.PublicKey
	LastSeen            time.Time     // Dernière fois qu'on a reçu un paquet de ce peer
	Root                []byte        // Root Merkle actuel
	Listroots           [][]byte      // Les 3 derniers roots reçus
	SharedKey           []byte        // Clé partagée (DH)
	Window              SlidingWindow // Fenêtre glissante pour suivi des performances
	MerkleDownloadStart time.Time     // Début du téléchargement Merkle
	MerkleDone          bool          // Merkle Terminé ou non
	RootChanged         bool          // le peer a récemment changé son arborescence
	State               PeerState     // état du peer
	Mupeer              sync.RWMutex  // Mutex
}

//
// ======================= UTILITAIRES DE NOM ET ADRESSES =======================
//

// Extraction du nom du peer depuis le body d'un Hello
func ExtractPeerName(body []byte) (string, error) {
	encrypted := IsChiffrementEnabled(body)
	if len(body) < ExtensionField {
		return "", fmt.Errorf("body trop court pour extensions")
	}
	var checksrv bool

	// Si la longueur du body est supérieure ou égale à 16, on vérifie la correspondance avec NameofServeurUDP
	if len(body) >= 4+len(NameofServeurUDP) {
		if bytes.Equal(body[ExtensionField:ExtensionField+len(NameofServeurUDP)], []byte(NameofServeurUDP)) {
			checksrv = true
		}
	} else {
		checksrv = false
	}

	var nameBytes []byte
	if encrypted == false || checksrv {
		nameBytes = body[ExtensionField:]
	} else {
		nameBytes = body[ExtensionField : len(body)-SizeSignature]
	}

	// retirer padding 0 éventuels
	i := bytes.IndexByte(nameBytes, 0)
	if i >= 0 {
		nameBytes = nameBytes[:i]
	}

	return string(nameBytes), nil
}

// Ajouter un peer dans la liste
// le boolean retourner signifie oui il a été ajouté non il a juste été modifié mais il existait déjà
func AddPeer(name string, addr *net.UDPAddr, key *ecdsa.PublicKey, connected PeerState) (*Peer, bool) {
	PeersMu.Lock()
	defer PeersMu.Unlock()
	p, exists := Peers[name]
	add := false
	if !exists {
		p = &Peer{Name: name}
		Peers[name] = p
		add = true
	}
	p.AddrIndex = 0
	p.ActiveAddr = addr
	p.PublicKey = key
	p.LastSeen = time.Now()
	p.State = connected
	p.Window = NewSlidingWindow(
		1,     // min
		32,    // initial
		10000, // max
	)
	return p, add
}

func FindPeer(name string) (*Peer, bool) {
	PeersMu.RLock()
	p, exists := Peers[name]
	PeersMu.RUnlock()
	return p, exists
}

//
// ======================= UTILITAIRES IP =======================
//

// ------------------------------------------------------------
// normalizeIP
// ------------------------------------------------------------
// Canonicalise une IP afin de pouvoir la comparer correctement.
// - IPv4            → IPv4 canonique (4 octets)
// - IPv4-mapped IPv6→ IPv4 canonique
// - IPv6 natif      → IPv6 (16 octets)
//
// IMPORTANT :
// Ne jamais comparer des IP directement sans normalisation,
// sinon IPv4 et IPv4-mapped IPv6 ne matcheront jamais.
func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}

	// IPv4 ou IPv4-mapped IPv6 (::ffff:x.y.z.w)
	if v4 := ip.To4(); v4 != nil {
		return v4
	}

	// IPv6 natif
	return ip.To16()
}

// ------------------------------------------------------------
// sameUDPAddr
// ------------------------------------------------------------
// Compare deux *net.UDPAddr de manière robuste :
// - IP normalisée
// - Port identique
func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}

	aIP := normalizeIP(a.IP)
	bIP := normalizeIP(b.IP)

	if aIP == nil || bIP == nil {
		return false
	}

	return aIP.Equal(bIP) && a.Port == b.Port
}

// ------------------------------------------------------------
// FindPeerByAddr
// ------------------------------------------------------------
// Tente d'identifier un peer à partir de l'adresse UDP source
// d'un paquet reçu.
//
// STRATÉGIE (dans cet ordre) :
//
//  1. ActiveAddr
//     → Connexion déjà établie (Hello OK)
//     → Cas normal (ping, data, maintenance)
//
//  2. Addresses[]
//     → Adresse connue mais pas encore validée
//     → Typiquement : NAT traversal, probing, ou tentative initiale
//
// NE MODIFIE PAS le peer (pas d'effet de bord).
func FindPeerByAddr(addr *net.UDPAddr) (*Peer, bool) {
	if addr == nil {
		return nil, false
	}

	PeersMu.RLock()
	defer PeersMu.RUnlock()

	// -----------------------------
	// 1) Recherche sur ActiveAddr
	// -----------------------------
	for _, p := range Peers {
		if p.ActiveAddr != nil && sameUDPAddr(p.ActiveAddr, addr) {
			return p, true
		}
	}

	// -----------------------------------
	// 2) Recherche dans Addresses[]
	// -----------------------------------
	for _, p := range Peers {
		for _, s := range p.Addresses {
			udpAddr, err := net.ResolveUDPAddr("udp", s)
			if err != nil {
				fmt.Println("erreur de resolution de l'addresse")
				continue
			}
			if sameUDPAddr(udpAddr, addr) {
				return p, true
			}
		}
	}

	return nil, false
}

// NextAddress retourne la prochaine adresse à tester pour le peer.
// Elle met à jour AddrIndex et ActiveAddr.
// Retourne l'adresse UDP, true si une adresse existe, false sinon.
func (p *Peer) NextAddress() (*net.UDPAddr, bool) {
	p.Mupeer.Lock()
	defer p.Mupeer.Unlock()

	if len(p.Addresses) == 0 {
		return nil, false
	}

	// Si index dépasse le nombre d'adresses, on recommence à 0
	if p.AddrIndex >= len(p.Addresses) {
		p.AddrIndex = 0
		return nil, false
	}

	// Récupère l'adresse à l'indice actuel
	addrString := p.Addresses[p.AddrIndex]

	udpAddr, err := net.ResolveUDPAddr("udp", addrString)
	if err != nil {
		// Si l'adresse est malformée, on passe à la suivante
		if debug {
			fmt.Println("NextAddress: impossible de résoudre", addrString)
		}
		p.AddrIndex++
		return p.NextAddress() // récursion pour passer à la suivante
	}

	// Met à jour l'adresse active
	p.ActiveAddr = udpAddr

	// On incrémente AddrIndex pour le prochain appel
	p.AddrIndex++

	return udpAddr, true
}

// SetPeerAddrIndex met à jour AddrIndex du peer pour correspondre à addr.
// Retourne true si l'adresse a été trouvée et index mise à jour, false sinon.
func SetPeerAddrIndex(peer *Peer, addr *net.UDPAddr) bool {
	if peer == nil || addr == nil {
		return false
	}

	peer.Mupeer.Lock()
	defer peer.Mupeer.Unlock()

	for i, s := range peer.Addresses {
		udpAddr, err := net.ResolveUDPAddr("udp", s)
		if err != nil {
			continue // ignorer les adresses malformées
		}

		if sameUDPAddr(udpAddr, addr) {
			peer.AddrIndex = i
			peer.ActiveAddr = udpAddr
			return true
		}
	}

	return false
}

// ------------------------------------------------------------
// debugUDPAddr (optionnel mais très utile)
// ------------------------------------------------------------
// Affiche une adresse UDP avec IP normalisée
// pour comprendre les problèmes IPv4 / IPv6.
func debugUDPAddr(label string, a *net.UDPAddr) {
	if a == nil {
		fmt.Println(label, ": <nil>")
		return
	}
	fmt.Printf(
		"%s → %s | IP brute=%v | IP normalisée=%v\n",
		label,
		a.String(),
		a.IP,
		normalizeIP(a.IP),
	)
}

//
// ======================= INITIALISATION ET MAJ DES PEERS =======================
//

// Initialise la map de peers connus à partir de noms
// (On ignore les peers qui n'ont pas d'adresses)
func InitPeersMap(names []string) {
	for _, name := range names {
		if name == NameofOurPeer {
			continue
		}
		_, exists := FindPeer(name) // j'ai changé ici
		if !exists {
			// on donne juste le nom et adresse, mais clé publique reste vide
			addresses, err := GetPeerAddresses(name)
			if len(addresses) == 0 {
				if debugPeer {
					fmt.Println("Pas d'adresses pour ce peer, on ignore")
				}
				continue
			}
			if err != nil {
				fmt.Println("Error lors de la récupération de l'adresse dans InitPeersMap du peer " + name)
				return
			}
			peer, ok := AddPeer(name, nil, nil, PeerDiscovered)

			if ok {
				peer.Addresses = addresses
				if debugPeer {
					fmt.Println("je viens d'ajouter l'adresse au peer "+name+" ses adresses sont ", addresses)
				}
			}
		}
	}
}

// Ajoute un root Merkle à un peer et met à jour la liste (pour les versions)
func AddRootToPeer(peer *Peer, hash []byte) error {

	if peer.Root != nil && bytes.Equal(peer.Root, hash) {
		if debugPeer {
			fmt.Println("Nouveau root reçu du peer inchangé " + peer.Name)
		}
		OnPeerEvent(peer, EventNewRoot, "(Inchangé)")
		return nil // pas de changement
	}
	if debugPeer {
		fmt.Println("Nouveau root reçu du peer " + peer.Name)
	}
	peer.Root = hash
	peer.Listroots = AddListRoot(peer.Listroots, hash)
	peer.RootChanged = true

	if OnPeerEvent != nil {
		OnPeerEvent(peer, EventNewRoot, hex.EncodeToString(hash))
	}

	return nil
}

// Ajoute un root Merkle à un peer identifié par adresse
func AddRootToPeerbyaddr(addr *net.UDPAddr, hash []byte) error {

	name, found := GetNameByAddr(addr)
	if !found {
		if debugPeer {
			fmt.Println("peer non trouvé pour l'adresse")
		}
		return fmt.Errorf("peer non trouvé pour l'adresse %s", addr.String())
	}
	peer, exists := FindPeer(name)
	if !exists {
		if debugPeer {
			fmt.Println("peer non trouvé pour le nom ")
		}
		return fmt.Errorf("peer non trouvé pour le nom %s", name)
	}
	AddRootToPeer(peer, hash)
	return nil
}

// Maintient uniquement les 3 derniers roots et supprime l'ancien
func AddListRoot(listRoots [][]byte, newRoot []byte) [][]byte {
	listRoots = append(listRoots, newRoot)
	if len(listRoots) > 3 {
		oldRoot := listRoots[0]
		listRoots = listRoots[1:] // supprime le plus ancien
		for _, p := range Peers {
			if bytes.Equal(p.Root, oldRoot) {
				return listRoots
			}
		}
		for _, l := range MyListroots {
			if bytes.Equal(l, oldRoot) {
				return listRoots
			}
		}

		clientStorage.DeleteMerkleTree(oldRoot)
		if debugPeer {
			fmt.Println("Suppression de l'ancien root de la liste et de l'arbre de Merkle :", oldRoot)
		}
	}
	return listRoots
}

// Retourne le nom du peer à partir d'une adresse
func GetNameByAddr(addr *net.UDPAddr) (string, bool) {

	for name, p := range Peers {
		if p.ActiveAddr != nil && p.ActiveAddr.IP.Equal(addr.IP) && p.ActiveAddr.Port == addr.Port {
			return name, true
		}
	}
	return "", false
}

// Rafraîchit la liste des peers : ajoute les nouveaux et supprime les absents
func RefreshPeers(peerNames []string) {

	// Créer un set pour savoir quels peers sont encore actifs
	activePeers := make(map[string]struct{})
	for _, name := range peerNames {
		if name == NameofOurPeer {
			continue
		}
		activePeers[name] = struct{}{}

		// Vérifier si le peer existe déjà
		peer, exists := FindPeer(name)

		// Récupérer ses adresses
		addresses, err := GetPeerAddresses(name)
		if err != nil {
			fmt.Println("-> Impossible de récupérer les adresses de", name)
			continue
		}
		if len(addresses) == 0 {
			if debugPeer {
				fmt.Println("Pas d'adresses pour ce peer, on l'ignore")
			}
			continue
		}

		if exists {
			if debugPeer {
				fmt.Println(" Peer déjà connu :", name)
			}
			peer.Addresses = addresses
			continue
		}

		// Ajouter un nouveau peer
		peer, added := AddPeer(name, nil, nil, PeerDiscovered)
		if !added {
			continue
		}
		peer.Addresses = addresses

		if debugPeer {
			fmt.Printf("➕ Nouveau peer ajouté : %s → %v\n", name, peer.Addresses)
		}
	}

	// Supprimer les peers qui ne sont plus dans la liste
	for name, peer := range Peers { // AllPeers retourne tous les peers connus
		if _, ok := activePeers[name]; !ok {
			if debugPeer {
				fmt.Printf("➖ Peer supprimé : %s\n", name)
			}
			DeletePeer(peer.Name)
		}
	}
}

// Supprimer un peer de la map des peers (Peers)
func DeletePeer(name string) {
	PeersMu.Lock()
	delete(Peers, name)
	PeersMu.Unlock()
}

// ======================= BAN / DÉBAN =======================
func AddBan(peer *Peer) {
	banMu.Lock()
	ban[peer.Name] = peer
	banMu.Unlock()
}

func DelBan(name string) {
	banMu.Lock()
	delete(ban, name)
	banMu.Unlock()
}

func IsBan(name string) bool {
	banMu.RLock()
	_, exists := ban[name]
	banMu.RUnlock()
	return exists
}

func IsBanByaddr(addr *net.UDPAddr) bool {
	name, found := GetNameByAddr(addr)
	if !found {
		return false
	}
	banMu.RLock()
	_, exists := ban[name]
	banMu.RUnlock()
	return exists
}

// ======================= UTILITAIRES DE CONNEXION =======================

// ---------------------------------
// Utilitaire pour connecter un peer
// ---------------------------------
func connectPeer(peer *Peer) {
	peer.Mupeer.Lock()
	if debugPeer {
		fmt.Println("connectPeer")
	}
	if peer.State == PeerDiscovered {
		if debugPeer {
			fmt.Println("Le peer n'est pas encore connecté")
		}
		peer.State = PeerAssociated
		peer.LastSeen = time.Now()
		peer.AddrIndex = 0
		if OnPeerEvent != nil {
			OnPeerEvent(peer, EventConnected, "")
		}
	} else {
		if OnPeerEvent != nil {
			OnPeerEvent(peer, EventConnected, "")
		}
	}

	if debugPeer {
		fmt.Println("fin connectPeer")
	}
	peer.Mupeer.Unlock()
}

// ----------------------
// Met à jour LastSeen
// ----------------------
func updateLastSeen(addr *net.UDPAddr) {
	peer, exist := FindPeerByAddr(addr)
	if exist {
		if debugPeer {
			fmt.Println("LastSeen mis à jour pour le peer : ", peer.Name)
		}
		peer.LastSeen = time.Now()
	}
}

// ----------------------------------------------------------------------------------
// Marque un peer comme déconnecté et réinitialise les attributs qui lui correspondent
// ----------------------------------------------------------------------------------
func DeconnectPeer(p *Peer) {
	p.Mupeer.Lock()
	p.State = PeerExpired
	p.AddrIndex = 0    // on retourne à l'index 0 de la liste d'adresse, si le peer se connecte on teste les addresses jusqu'à qu'il y en ait une qui fonctionne
	p.ActiveAddr = nil // plus d'adresse active
	p.Mupeer.Unlock()
	if debugPeer {
		fmt.Println("peer déconnecté réussi")
	}
	OnPeerEvent(p, EventDisconnected, "")
}

// ---------------------------------------------------
// Commence une demande de donnée à un peer spécifique
// ---------------------------------------------------
func StartAskMerkle(peer *Peer) {
	peer.MerkleDownloadStart = time.Now()
	peer.MerkleDone = false
}

func IsPeerDisconnected(peer *Peer) bool {
	peer.Mupeer.RLock()
	state := peer.State
	peer.Mupeer.RUnlock()

	return state == PeerExpired
}

// pas de changement d'addresse au cours de la connexion
func NoChangeAddr(peer *Peer, addr *net.UDPAddr) {
	peer.AddrIndex = -1
	peer.ActiveAddr = addr
}
