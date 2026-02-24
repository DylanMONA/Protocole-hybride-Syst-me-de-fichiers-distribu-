package client

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

/*
Ce fichier gère la communication REST/HTTPS avec le serveur central
ainsi que l'enregistrement de la clé publique et le maintien du peer vivant.
*/

// ============================
// Variables globales
// ============================
var (
	NameofOurPeer    = "jouer"
	ServerURL        = "https://jch.irif.fr:8443" // URL du serveur central HTTPS
	AddrServeurUDP   = "jch.irif.fr:8443"         // Adresse serveur UDP
	NameofServeurUDP = "jch.irif.fr"              // Nom serveur
	debugServer      = false                      // Affiche les logs de debug si true
	peersETag        = ""                         // ETag pour cache HTTP
)

// ============================
// Fonctions de base HTTP/REST
// ============================

// ReadHTTP effectue un GET HTTP sur le serveur et retourne le corps.
func ReadHTTP(path string) ([]byte, error) {
	url := ServerURL + path
	if debugServer {
		fmt.Println("→ GET", url)
	}

	resp, err := http.Get(url)
	if err != nil {
		if debugServer {
			fmt.Println("❌ Erreur GET ReadHTTP:", err)
		}
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if debugServer {
			fmt.Println("❌ Erreur lecture body ReadHTTP:", err)
		}
		return nil, err
	}
	return body, nil
}

// GetPeerListIfChanged récupère la liste des peers seulement si elle a changé
// grâce à l'en-tête HTTP ETag.
func GetPeerListIfChanged() ([]string, bool, error) {
	req, err := http.NewRequest("GET", ServerURL+"/peers/", nil)
	if err != nil {
		return nil, false, fmt.Errorf("création requête GET /peers/ échouée : %w", err)
	}

	if peersETag != "" {
		req.Header.Set("If-None-Match", peersETag)
	}

	clientHTTP := &http.Client{Timeout: 10 * time.Second}
	resp, err := clientHTTP.Do(req)
	if err != nil {
		if debugServer {
			fmt.Println("Erreur Do GetPeerListIfChanged :", err)
		}
		return nil, false, fmt.Errorf("GET /peers/ échoué : %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		if debugServer {
			fmt.Println("✔ Peers inchangés (HTTP 304)")
		}
		return nil, false, nil
	}

	// Mettre à jour ETag si présent
	if etag := resp.Header.Get("ETag"); etag != "" {
		peersETag = etag
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {

		if debugServer {
			fmt.Println("❌ Erreur lecture body ReadHTTP:", err)
		}
		return nil, false, fmt.Errorf("lecture body GET /peers/ échouée : %w", err)
	}

	peers := strings.Split(strings.TrimSpace(string(body)), "\n")
	return peers, true, nil
}

// GetPeerList récupère la liste complète des peers depuis le serveur
func GetPeerList() ([]string, error) {
	body, err := ReadHTTP("/peers/")
	if err != nil {
		return nil, fmt.Errorf("GET /peers/ échoué : %w", err)
	}

	if debugServer {
		fmt.Println("Body GET /peers/ :", string(body))
	}

	peers := strings.Split(strings.TrimSpace(string(body)), "\n")
	return peers, nil
}

// GetPeerKey récupère la clé publique d’un peer depuis le serveur
func GetPeerKey(name string) (*ecdsa.PublicKey, error) {
	body, err := ReadHTTP("/peers/" + name + "/key")
	if err != nil {
		if debugServer {
			fmt.Println("❌ Erreur GET clé peer:", err)
		}
		return nil, err
	}

	pub, err := ParsePublicKey(body)
	if err != nil {
		if debugServer {
			fmt.Printf("❌ Erreur parsing clé publique du peer %s: %v\n", name, err)
		}
		return nil, err
	}
	return pub, nil
}

// GetPeerAddresses récupère les adresses connues d’un peer
func GetPeerAddresses(name string) ([]string, error) {
	body, err := ReadHTTP("/peers/" + name + "/addresses")
	if err != nil {
		if debugServer {
			fmt.Println("❌ Erreur GET adresses peer:", err)
		}
		return nil, err
	}

	lines := strings.Split(string(body), "\n")
	addrs := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			addrs = append(addrs, l)
		}
	}
	return addrs, nil
}

// ============================
// Enregistrement de la clé publique
// ============================

// RegisterKey enregistre la clé publique du peer auprès du serveur central.
func RegisterKey(name string, pubKey []byte) error {
	req, err := http.NewRequest(
		"PUT",
		ServerURL+"/peers/"+name+"/key",
		bytes.NewBuffer(pubKey),
	)
	if err != nil {
		return fmt.Errorf("création requête PUT échouée : %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	clientHTTP := &http.Client{Timeout: 30 * time.Second}
	resp, err := clientHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("PUT /peers/%s/key échoué : %w", name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if debugServer {
			fmt.Println("❌ Erreur lecture body ReadHTTP:", err)
		}
		return err
	}
	fmt.Printf("PUT /peers/%s/key → HTTP %d %s\n", name, resp.StatusCode, resp.Status)
	if len(body) > 0 && debugServer {
		fmt.Println("Body serveur :", string(body))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("enregistrement échoué : HTTP %d (%s)", resp.StatusCode, string(body))
	}

	if debugServer {
		fmt.Println("✅ Clé publique enregistrée avec succès sur le serveur")

		// Vérification de la clé côté serveur
		peerKey, err := GetPeerKey(NameofOurPeer)
		if err != nil {
			fmt.Println("⚠️ Impossible de récupérer la clé depuis le serveur :", err)
			return err
		}
		keyBytes := SerializePublicKey(peerKey)

		fmt.Printf("🔑 Clé publique du peer serveur : %x\n", keyBytes)
		if bytes.Equal(pubKey, keyBytes) {
			fmt.Println("✅ Clé locale et serveur identiques")
		} else {
			fmt.Println("❌ Clé locale et serveur diffèrent !")
			fmt.Printf("Local  : %x\nServeur: %x\n", pubKey, keyBytes)
		}
	}
	return nil
}

// ============================
// Handshake et maintien vivant
// ============================

// HandShakeWithServer effectue un handshake UDP avec le serveur
func HandShakeWithServer(conn *net.UDPConn, priv *ecdsa.PrivateKey, addrServeur *net.UDPAddr) error {
	peer, ok := FindPeer(NameofServeurUDP)
	if !ok {
		return fmt.Errorf("aucun peer avec ce nom")
	}
	NoChangeAddr(peer, addrServeur)
	SendHello(conn, priv, peer)
	return nil
}
