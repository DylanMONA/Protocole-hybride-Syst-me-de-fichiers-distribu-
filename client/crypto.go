package client

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"myp2p/clientStorage"
	"net"
)

const (
	AESGCMNonceSize = 12    // taille du nonce pour AES-GCM
	chiffre         = false // Chiffrement activé ou non
)

var debugCrypto = true

// -------------------------
// Génération de clés ECDSA
// -------------------------

// GenerateKeyPair génère une paire clé privée / publique ECDSA sur P256
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {

		fmt.Println("Erreur génération clé ECDSA :", err)

		return nil, nil, err
	}
	if debugCrypto {
		fmt.Println("Clé ECDSA générée avec succès")
	}
	return priv, &priv.PublicKey, nil
}

// -------------------------
// Sérialisation / Parsing
// -------------------------

// SerializePublicKey convertit une clé publique en 64 bytes (32 bytes X + 32 bytes Y)
func SerializePublicKey(pub *ecdsa.PublicKey) []byte {
	formatted := make([]byte, 64)
	pub.X.FillBytes(formatted[:clientStorage.HashSize])
	pub.Y.FillBytes(formatted[clientStorage.HashSize:])
	if debugCrypto {
		fmt.Println("Clé publique sérialisée :", formatted)
	}
	return formatted
}

// ParsePublicKey reconstruit une clé publique à partir de 64 bytes
func ParsePublicKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) != 64 {
		if debugCrypto {
			fmt.Println("Erreur ParsePublicKey : data != 64 bytes")
		}
		return nil, errors.New("clé publique invalide, doit faire 64 bytes")
	}
	var x, y big.Int
	x.SetBytes(data[:clientStorage.HashSize])
	y.SetBytes(data[clientStorage.HashSize:])
	if debugCrypto {
		fmt.Println("Clé publique parsée avec succès")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &x,
		Y:     &y,
	}, nil
}

// -------------------------
// Signature et vérification
// -------------------------

// SignMessage signe un message avec la clé privée ECDSA
func SignMessage(priv *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		if debugCrypto {
			fmt.Println("Erreur signature :", err)
		}
		return nil, err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:clientStorage.HashSize])
	s.FillBytes(signature[clientStorage.HashSize:])
	if debugCrypto {
		fmt.Println("Message signé :", signature)
	}
	return signature, nil
}

// VerifyMessage vérifie la signature d'un message avec la clé publique
func VerifyMessage(pub *ecdsa.PublicKey, message []byte, signature []byte) (bool, error) {
	if signature == nil || message == nil {
		if debugCrypto {
			fmt.Println("Erreur VerifyMessage : signature ou message nil")
		}
		return false, errors.New("signature ou message signé vaut nil")
	}
	if len(signature) != 64 {
		if debugCrypto {
			fmt.Println("Erreur VerifyMessage : signature != 64 bytes")
		}
		return false, errors.New("signature invalide, doit faire 64 bytes")
	}
	hash := sha256.Sum256(message)
	var r, s big.Int
	r.SetBytes(signature[:clientStorage.HashSize])
	s.SetBytes(signature[clientStorage.HashSize:])
	valid := ecdsa.Verify(pub, hash[:], &r, &s)
	if debugCrypto {
		if valid {
			fmt.Println("Signature valide")
		} else {
			fmt.Println("Signature invalide")
		}
	}
	return valid, nil
}

// -------------------------
// Intégrité des données
// -------------------------

// VerifyDataIntegrity vérifie que le hash du corps correspond au hash demandé
func VerifyDataIntegrity(body []byte, requestHash []byte) bool {
	if len(body) < clientStorage.HashSize {
		if debugCrypto {
			fmt.Println("Message trop court pour contenir un hash")
		}
		return false
	}

	receivedHash := body[:clientStorage.HashSize]
	data := body[clientStorage.HashSize:]

	computedHash := clientStorage.Sha(data)
	if !bytes.Equal(requestHash, computedHash) {
		if debugCrypto {
			fmt.Println("Intégrité des données compromise : hash data invalide")
		}
		return false
	}
	if !bytes.Equal(requestHash, receivedHash) {
		if debugCrypto {
			fmt.Println("Intégrité des données compromise : hash reçu != hash demandé")
		}
		return false
	}

	if debugCrypto {
		fmt.Println("Données reçues intactes, hash correct")
	}
	return true
}

// -------------------------
// Vérification de signature par peer
// -------------------------

func VerifSign(addr *net.UDPAddr, message []byte, sig []byte) bool {
	peer, find := FindPeerByAddr(addr)
	if !find {
		if debugCrypto {
			fmt.Println("Peer inconnu pour VerifSign :", addr)
		}
		return false
	}
	peerkey, err := GetPeerKey(peer.Name)
	if err != nil {
		fmt.Printf("Erreur GetPeerKey pour %s: %v\n", peer.Name, err)
		return false
	}
	peer.PublicKey = peerkey
	if peer.PublicKey == nil {
		fmt.Println("Clé publique nil pour le peer", peer.Name)
		return false
	}

	check, err := VerifyMessage(peer.PublicKey, message, sig)
	if err != nil {
		if debugCrypto {
			fmt.Println("Erreur VerifyMessage :", err)
		}
		return false
	}
	if !check {
		if debugCrypto {
			fmt.Println("Signature invalide pour le message reçu")
		}
		return false
	}
	if debugCrypto {
		fmt.Println("Signature valide pour le message reçu de", peer.Name)
	}
	return true
}

// -------------------------
// Diffie-Hellman ECDH
// -------------------------

// ComputeSharedKey calcule la clé partagée à partir de la clé privée locale et de la clé publique du peer
func ComputeSharedKey(privateKey *ecdsa.PrivateKey, peerPublicKey *ecdsa.PublicKey) ([]byte, error) {
	// ScalarMult calcule (x, y) = privateKey.D * peerPublicKey
	x, _ := peerPublicKey.Curve.ScalarMult(peerPublicKey.X, peerPublicKey.Y, privateKey.D.Bytes())

	// On n'utilise que x pour dériver la clé symétrique
	xBytes := make([]byte, 32)
	x.FillBytes(xBytes)

	sharedKey := sha256.Sum256(xBytes) // clé symétrique de 32 bytes
	if debugCrypto {
		fmt.Println("Clé partagée calculée :", sharedKey[:])
	}
	return sharedKey[:], nil
}

// -------------------------
// Chiffrement AES-GCM
// -------------------------

// encryptAESGCM chiffre un message avec AES-GCM
func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {

		fmt.Println("Erreur création cipher AES :", err)

		return nil, err
	}

	nonce := make([]byte, AESGCMNonceSize)
	if _, err := rand.Read(nonce); err != nil {

		fmt.Println("Erreur génération nonce :", err)

		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {

		fmt.Println("Erreur création GCM :", err)

		return nil, err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	if debugCrypto {
		fmt.Println("Message chiffré :", ciphertext)
	}
	return ciphertext, nil
}

// decryptAESGCM déchiffre un message AES-GCM
func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < AESGCMNonceSize {
		return nil, errors.New("ciphertext trop court")
	}

	block, err := aes.NewCipher(key)
	if err != nil {

		fmt.Println("Erreur création cipher AES :", err)

		return nil, err
	}

	nonce := ciphertext[:AESGCMNonceSize]
	ciphertext = ciphertext[AESGCMNonceSize:]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {

		fmt.Println("Erreur création GCM :", err)

		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {

		fmt.Println("Erreur déchiffrement GCM :", err)

		return nil, err
	}
	if debugCrypto {
		fmt.Println("Message déchiffré :", plaintext)
	}
	return plaintext, nil
}
