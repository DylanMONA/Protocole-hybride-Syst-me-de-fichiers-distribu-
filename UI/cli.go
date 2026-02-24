package UI

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"myp2p/client"
	"myp2p/clientStorage"
	"net"
	"os"
	"strings"
)

/* -------------------------------------------------------------------------
   COMMANDES CLI
   ------------------------------------------------------------------------- */

const (
	CMD_HANDSHAKE = "HANDSHAKE"
	CMD_SHOW      = "SHOW"
	CMD_ASK       = "ASK"
	CMD_MERKLE    = "MERKLE"
)

/* -------------------------------------------------------------------------
   PEERS
   ------------------------------------------------------------------------- */

func ShowPeers() {
	fmt.Println("|-------------------- PEERS --------------------|")
	for name, p := range client.Peers {
		status := "disconnected"
		if p.State == client.PeerAssociated {
			status = "connected"
		}
		fmt.Printf("- %s [%s]\n", name, status)
	}
	fmt.Println("|------------------------------------------------|")
}

/* -------------------------------------------------------------------------
   ASK COMMAND
   ------------------------------------------------------------------------- */

func ProcessAskCommand(conn *net.UDPConn, priv *ecdsa.PrivateKey, parts []string) {

	if len(parts) < 3 {
		fmt.Println("Usage:")
		fmt.Println("  ASK ROOT <peer>")
		fmt.Println("  ASK DATA <file> <peer>")
		fmt.Println("  ASK DATA ALL <peer> [LAST|PREV|OLD]")
		return
	}

	switch strings.ToUpper(parts[1]) {

	/* -------------------- ASK ROOT -------------------- */
	case "ROOT":
		peerName := parts[2]
		peer, ok := client.FindPeer(peerName)
		if !ok {
			fmt.Println("Peer inconnu :", peerName)
			return
		}
		if peer.ActiveAddr == nil {
			fmt.Println("Handshake requis avec", peerName)
			return
		}
		if client.IsBan(peerName) {
			fmt.Println(" Peer banned ", peerName)
			id := client.GenerateId()
			msg, err := client.BuildMessage(id, client.Error, []byte{}, nil, false)
			if err != nil {
				fmt.Println("erreur builder message error", peerName)
				return
			}
			client.SendMessage(conn, peer.ActiveAddr, msg)
			return
		}

		id := client.GenerateId()
		msg, err := client.BuildMessage(id, client.RootRequest, []byte{}, priv, false)
		if err != nil {
			fmt.Println("erreur builder rootRequest", peerName)
			return
		}

		client.CreateTransaction(id, peer, peer.ActiveAddr, client.RootRequest, msg, client.Retries)
		client.SendMessage(conn, peer.ActiveAddr, msg)

	case "MERKLE":
		peerName := parts[2]
		peer, ok := client.FindPeer(peerName)
		if !ok {
			fmt.Println("Peer inconnu :", peerName)
			return
		}
		// le peer doit être connecté et avoir un handshake complet
		if peer.ActiveAddr == nil {
			fmt.Println("Peer non connecté :", peerName)
			return
		}

		// la racine doit être connue
		if peer.Root == nil {
			fmt.Println("Faire le ask root :", peerName)
			return
		}
		// marquer le peer comme en train de télécharger son Merkle
		client.StartAskMerkle(peer)

		// si le root du peer n'a pas changé on dit directement : " C'est bon téléchargé ! "
		if peer.RootChanged == false {
			peer.MerkleDone = true

		}

		// création de la requête DatumRequest
		id := client.GenerateId()
		msg, err := client.BuildDatumRequest(id, peer.Root)
		if err != nil {
			fmt.Println("erreur datum builder :", peerName)
			return
		}

		// création d'une transaction pour suivre la requête
		client.CreateTransaction(id, peer, peer.ActiveAddr, client.DatumRequest, msg, client.Retries)

		// envoi de la requête
		client.SendMessage(conn, peer.ActiveAddr, msg)

		peer.RootChanged = false // On a récupéré les changements
	/* -------------------- ASK DATA -------------------- */
	case "DATA":

		if len(parts) < 4 {
			fmt.Println("Usage: ASK DATA <file|ALL> <peer> [LAST|PREV|OLD]")
			return
		}

		target := parts[2]
		peerName := parts[3]

		peer, ok := client.FindPeer(peerName)
		if !ok {
			fmt.Println("Peer inconnu :", peerName)
			return
		}
		if peer.Root == nil {
			fmt.Println("Root inconnu — faites ASK ROOT avant")
			return
		}

		/* ---- ASK DATA <file> <peer> ---- */
		if strings.ToUpper(target) != "ALL" {

			hash, found := clientStorage.FindName([]byte(target))
			if !found {
				fmt.Println("Fichier introuvable dans le Merkle")
				return
			}

			fmt.Println("→ Téléchargement du fichier", target)
			err := clientStorage.RebuildNode(hash, "OUTPUT/"+peer.Name+"/"+target)
			if err != nil {
				fmt.Println("Erreur téléchargement :", err)
			}
			return
		}

		/* ---- ASK DATA ALL <peer> [version] ---- */
		version := "LAST"
		if len(parts) >= 5 {
			version = strings.ToUpper(parts[4])
		}

		var root []byte
		switch version {
		case "LAST":
			root = peer.Root
		case "PREV":
			if len(peer.Listroots) > 1 {
				root = peer.Listroots[1]
			}
		case "OLD":
			if len(peer.Listroots) > 2 {
				root = peer.Listroots[2]
			}
		default:
			fmt.Println("Version inconnue :", version)
			return
		}

		if root == nil {
			fmt.Println("Version non disponible")
			return
		}

		fmt.Println("→ Téléchargement complet du peer", peer.Name)
		err := clientStorage.RebuildNode(root, "OUTPUT/"+peer.Name)
		if err != nil {
			fmt.Println("Erreur téléchargement :", err)
		}

	default:
		fmt.Println("Sous-commande ASK inconnue")
	}
}

/* -------------------------------------------------------------------------
   MERKLE
   ------------------------------------------------------------------------- */

func ProcessMerkle(parts []string) {
	if len(parts) != 2 {
		fmt.Println("Usage: MERKLE <peer>")
		return
	}

	peer, ok := client.FindPeer(parts[1])
	if !ok {
		fmt.Println("Peer inconnu")
		return
	}
	if peer.Root == nil {
		fmt.Println("Root inconnu — faites ASK ROOT avant")
		return
	}

	fmt.Println("Merkle tree de", peer.Name)
	clientStorage.PrintTree(clientStorage.MerkleMap[hex.EncodeToString(peer.Root)], 0)
}

/* -------------------------------------------------------------------------
   MAIN DISPATCH
   ------------------------------------------------------------------------- */

func ProcessCommand(conn *net.UDPConn, priv *ecdsa.PrivateKey, cmd string) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return
	}

	switch strings.ToUpper(parts[0]) {

	case CMD_SHOW:
		ShowPeers()

	case CMD_HANDSHAKE:
		for _, name := range parts[1:] {
			peer, ok := client.FindPeer(name)
			if ok {
				client.HelloToPeer(conn, priv, peer)
				fmt.Println("→ Handshake avec", name)
			}
		}

	case CMD_ASK:
		ProcessAskCommand(conn, priv, parts)

	case CMD_MERKLE:
		ProcessMerkle(parts)

	default:
		fmt.Println("Commande inconnue")
	}
}

/* -------------------------------------------------------------------------
   LOOP
   ------------------------------------------------------------------------- */

func StartCLI(conn *net.UDPConn, priv *ecdsa.PrivateKey) {
	reader := bufio.NewScanner(os.Stdin)

	fmt.Println("CLI prêt.")
	fmt.Println("Commands: SHOW | HANDSHAKE | ASK | MERKLE")

	for {
		fmt.Print("> ")
		if !reader.Scan() {
			return
		}
		ProcessCommand(conn, priv, reader.Text())
	}
}
