package client

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"sync"
	"time"
)

//
// ======================= GESTION DES TRANSACTIONS =======================
//

var debugTransaction = false

// Nombre maximum de tentatives d’envoi avant abandon
var Retries = 4

// TxState représente l’état courant d’une transaction réseau
type TxState uint8

const (
	// Transaction en attente de réponse
	TxPending TxState = iota

	// Transaction devant être renvoyée
	TxResend

	// Changement d’adresse après échec d’un Hello
	TxChangeAddrHello

	// Changement d’adresse lors d’une tentative de traversée NAT
	TxChangeAddrNat

	// Transaction terminée (succès ou abandon)
	TxDone
)

// Transaction représente un échange réseau fiable au-dessus d’UDP.
// Elle encapsule le message, son état, le peer cible et la logique de retry.

type Transaction struct {
	Id      uint32
	Peer    *Peer
	Addr    *net.UDPAddr
	MsgType uint8
	SentAt  time.Time
	Retries int
	Timeout time.Duration
	Msg     []byte
	State   TxState
	DhPriv  *ecdsa.PrivateKey
}

// Mutex protégeant l’accès concurrent aux transactions
var (
	txMu         sync.Mutex
	Transactions = map[uint32]*Transaction{}
)

//
// ======================= GESTION DE LA MAP DE TRANSACTIONS =======================
//

// Ajoute une transaction à la map globale
// Paramètre :
//   - tx : transaction à enregistrer
func addTransaction(tx *Transaction) {
	txMu.Lock()
	Transactions[tx.Id] = tx
	txMu.Unlock()
}

//
// ======================= NETTOYAGE ET RETRY =======================
//

// Boucle périodique de nettoyage des transactions expirées.
// Appelle CleanupTransactions à intervalle régulier.
// Paramètres :
//   - conn : connexion UDP utilisée pour les renvois
//   - priv : clé privée locale
func CleanupTransactionsLoop(conn *net.UDPConn, priv *ecdsa.PrivateKey) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		CleanupTransactions(conn, priv)
	}
}

// Vérifie l’état de toutes les transactions actives.
// Gère les timeouts, retries, changements d’adresse et suppressions.
// Paramètres :
//   - conn : connexion UDP utilisée pour les renvois
//   - priv : clé privée locale
func CleanupTransactions(conn *net.UDPConn, priv *ecdsa.PrivateKey) {
	now := time.Now()

	txMu.Lock()
	for id, tx := range Transactions {

		if tx.State == TxDone {
			// si le message est résolu alors on le supprime
			delete(Transactions, id)
			continue
		}
		if now.Sub(tx.SentAt) <= tx.Timeout {
			// si le timing est encore bon pour cette transaction on passe à la suivante
			continue
		}

		if tx.Retries <= 0 {
			if tx.MsgType == DatumRequest && tx.Peer != nil {
				tx.Peer.Window.OnTimeout()
			}
			switch tx.MsgType {
			case Hello:
				tx.State = TxChangeAddrHello
				// si entre temps le peer est connecté
				tx.Peer.Mupeer.RLock()
				if tx.Peer.State == PeerAssociated {
					delete(Transactions, id)
				}
				tx.Peer.Mupeer.RUnlock()
				// si c'était un hello on retente avec une nouvelle adresse ou on démarre la traversée de nat
				if debugTransaction {
					fmt.Println("expired Hello")
				}
			case NatTraversalRequest:
				// si le message qui a été envoyé était un NatTraversal on le retente si y'a une autre adresse sinon on abandonne
				tx.State = TxChangeAddrNat
				// si entre temps le peer est connecté
				tx.Peer.Mupeer.RLock()
				if tx.Peer.State == PeerAssociated {
					delete(Transactions, id)
				}
				tx.Peer.Mupeer.RUnlock()
				if debugTransaction {
					fmt.Println("expired Nat")
				}
			default:
				// dans tous les autres cas le message avec le délai dépassé est supprimé
				delete(Transactions, id)
			}

			continue
		}

		// Pour après
		tx.Timeout *= 2
		tx.SentAt = now
		tx.Retries--

		if tx.Timeout > 64*time.Second {
			// timeout alors on supprime la transaction
			delete(Transactions, id)
			continue
		}

		tx.State = TxResend
	}
	// on récupère toutes les transactions qui ne sont pas en vol (celle qui doivent etre renvoyé etc...)
	var list []*Transaction
	for _, tx := range Transactions {
		if tx.State != TxPending {
			list = append(list, tx)
		}
	}

	txMu.Unlock()

	// pour toutes les transactions on effectue les actions spécifiques
	// exécution
	for _, tx := range list {
		//addTransaction(tx)
		switch tx.State {
		case TxResend:
			// les renvoie pour le hello et Natraversal passe également par là
			tx.State = TxPending // on la remet en vol
			SendMessage(conn, tx.Addr, tx.Msg)
		case TxChangeAddrHello:
			tx.State = TxDone // on la termine car une nouvelle transaction est créée pour la nouvelle adresse ou le nat
			if tx.Peer.State == PeerDiscovered {
				if !HelloToPeer(conn, priv, tx.Peer) {
					OnPeerEvent(tx.Peer, EventConnectionFailed, "Hello non abouti, On teste la traversée de NAT")
					tx.Peer.Mupeer.Lock()
					tx.Peer.State = PeerWaitHelloNat
					tx.Peer.Mupeer.Unlock()
					TryNatTraversal(conn, priv, tx.Peer)
				}
			}
		case TxChangeAddrNat:
			tx.State = TxDone // on la termine car une nouvelle transaction est créée à chaque nouvelle adresse

			// on récupère l'état du peer
			tx.Peer.Mupeer.RLock()
			state := tx.Peer.State
			tx.Peer.Mupeer.RUnlock()
			// s'il est entrain d'attendre un hello parce qu'il a lancé un natTraversal
			// et que la transaction indique un état de changement d'adresse pour le nat
			if state == PeerWaitHelloNat {
				// alors on teste de renvoyer un nouveau nat avec une nouvelle addresse
				if !TryNatTraversal(conn, priv, tx.Peer) {
					// si y'a plus d'adresse à tester on marque l'échec
					OnPeerEvent(tx.Peer, EventConnectionFailed, "NatTraversalRequest2 non abouti")
					if debugTransaction {
						fmt.Println("NatTraversal: Fin d'envoie de l'essai")
					}
				}
			}

		}

	}
}

//
// ======================= RÉSOLUTION DES TRANSACTIONS =======================
//

// Marque une transaction comme terminée à la réception d’une réponse.
// Paramètre :
//   - id : identifiant de la transaction
//
// Retour :
//   - transaction correspondante
//   - booléen indiquant si elle existait
func resolveTransaction(id uint32) (*Transaction, bool) {
	txMu.Lock()
	defer txMu.Unlock()

	tx, ok := Transactions[id]
	if ok {
		tx.State = TxDone
	}
	return tx, ok
}

// Crée et enregistre une nouvelle transaction réseau.
// Paramètres :
//   - id       : identifiant unique
//   - p        : peer cible
//   - addr     : adresse UDP utilisée
//   - msgType  : type du message
//   - payload  : message à envoyer
//   - rootHash : hash associé (ex : Merkle root)
//   - retries  : nombre de tentatives
//
// Retour :
//   - pointeur vers la transaction créée
func CreateTransaction(
	id uint32,
	p *Peer,
	addr *net.UDPAddr,
	msgType uint8,
	msg []byte,
	retries int,
) *Transaction {

	tx := &Transaction{
		Id:      id,
		Peer:    p,
		Addr:    addr,
		MsgType: msgType,
		SentAt:  time.Now(),
		Timeout: 1 * time.Second,
		Retries: retries,
		Msg:     msg,
		State:   TxPending,
	}

	addTransaction(tx)
	return tx
}
