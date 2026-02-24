package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"myp2p/UI"
	"myp2p/client"
	"myp2p/clientStorage"
	"myp2p/generateKey"
	"net"
	"os"
)

// Activer/désactiver les messages de debug
const debugMain = true

func main() {
	// ============================
	// 0. Préparation des dossiers & chemins
	// ============================
	keyDir := "keys2"
	privPath := keyDir + "/priv.pem"
	pubPath := keyDir + "/pub.pem"

	if err := os.MkdirAll(keyDir, 0700); err != nil {
		log.Fatal("Impossible de créer le dossier keys/:", err)
	}

	// ============================
	// 1. Charger ou générer une paire de clés ECDSA
	// ============================
	var priv *ecdsa.PrivateKey
	var pub *ecdsa.PublicKey
	var err error

	priv, pub, err = generateKey.LoadKeyPair(privPath, pubPath)
	if err == nil {
		if debugMain {
			fmt.Println("🔑 Paire de clés chargée depuis le disque.")
		}
	} else {
		if debugMain {
			fmt.Println("⚠️ Pas de clé trouvée → génération d’une nouvelle paire...")
		}
		priv, pub, err = client.GenerateKeyPair()
		if err != nil {
			log.Fatal("Erreur génération clé :", err)
		}
		if err := generateKey.SaveKeyPair(priv, pub, privPath, pubPath); err != nil {
			log.Fatal("Erreur sauvegarde clé :", err)
		}
		if debugMain {
			fmt.Println("🔐 Nouvelle paire générée et sauvegardée.")
		}
	}

	// ============================
	// 2. Enregistrement de la clé auprès du serveur
	// ============================
	pubBytes := client.SerializePublicKey(pub)
	if err := client.RegisterKey(client.NameofOurPeer, pubBytes); err != nil {
		log.Fatal("Erreur lors de l'enregistrement du peer :", err)
	}
	if debugMain {
		fmt.Println("📡 Peer enregistré sur le serveur.")
	}
	// ============================
	// 3. Récupérer la liste des peers connus
	// ============================
	peers, err := client.GetPeerList()
	if err != nil {
		log.Fatal("Erreur récupération peer list :", err)
	}
	if debugMain {
		fmt.Println("🌐 Peers connus :", peers)
	}
	// ============================
	// 4. Ouvrir un socket UDP local
	// ============================
	if debugMain {
		fmt.Println("Ouvrir une socket UDP locale...")
	}
	raddr, err := net.ResolveUDPAddr("udp", client.AddrServeurUDP)
	if err != nil {
		fmt.Println("erreur resolution addr udp serveur main.go")
		return
	}
	addr := net.UDPAddr{
		IP:   net.IPv6unspecified,
		Port: 7513, //59562 15546 1234
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatal("Impossible d'écouter sur le port UDP :", err)
	}
	defer conn.Close()

	if debugMain {
		fmt.Println("🟢 Socket UDP ouverte :", addr.String())
	}
	// ============================
	// 5. Initialiser la map de peers
	// ============================
	client.InitPeersMap(peers)
	if debugMain {
		fmt.Println("===== debugMain PEERS ADDRESSES =====")
		for name, p := range client.Peers {
			fmt.Printf("Peer: %s\n", name)
			fmt.Printf("  len(Addresses) = %d\n", len(p.Addresses))
			for i, addr := range p.Addresses {
				fmt.Printf("  [%d] %q (len=%d)\n", i, addr, len(addr))
			}
			fmt.Println()
		}
		fmt.Println("================================")
	}

	// ============================
	// 6. Lancer les routines P2P en arrière-plan
	// ============================
	go client.ResponseHandler(conn, priv)
	go client.RequestHandler(conn, priv)
	go client.CaptureMessage(conn, priv)
	go client.CleanupTransactionsLoop(conn, priv)
	go client.CheckRoots(conn, priv)
	go client.DatumScheduler(conn)

	// Handshake initial avec le serveur
	if debugMain {
		fmt.Println("Handshake avec le serveur...")
	}
	go client.KeepAlive(conn, priv, pub, raddr)

	// ============================
	// 7. Construire le hashRoot du répertoire DATA
	// ============================
	fmt.Printf("\n\n=== Test du répertoire: %s ===\n", UI.DATA_DIRECTORY)
	rootNode, err := clientStorage.BuildMerkleNode(UI.DATA_DIRECTORY)
	if err != nil {

		fmt.Println("Erreur lors de la construction du Merkle :", err)

		return
	}
	clientStorage.RootHash = clientStorage.Sha(rootNode)
	client.MyListroots = client.AddListRoot(client.MyListroots, clientStorage.RootHash)
	fmt.Println("Hash de la racine :", hex.EncodeToString(clientStorage.RootHash))

	// ============================
	// 8. Démarrage de l'interface graphique
	// ============================
	if debugMain {
		fmt.Println("Démarrage de la GUI...")
	}
	UI.StartGUI(conn, priv)
}
