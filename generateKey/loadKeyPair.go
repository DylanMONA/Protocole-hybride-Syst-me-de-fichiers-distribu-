package generateKey

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadKeyPair charge une paire de clés ECDSA depuis le disque.
//
// La fonction lit une clé privée et une clé publique au format PEM,
// les décode et les reconstruit sous forme d’objets ECDSA utilisables.
// Si la clé privée n’existe pas, une erreur os.ErrNotExist est retournée
// afin d’indiquer à l’appelant qu’une génération de clés est nécessaire.
//
// Paramètres :
//   - privPath : chemin vers le fichier contenant la clé privée PEM
//   - pubPath  : chemin vers le fichier contenant la clé publique PEM
//
// Retour :
//   - *ecdsa.PrivateKey : clé privée chargée
//   - *ecdsa.PublicKey  : clé publique chargée
//   - error             : erreur éventuelle (lecture, parsing, absence de clé)
func LoadKeyPair(privPath, pubPath string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {

	// Vérifie l’existence de la clé privée
	// Si elle n’existe pas, l’appelant devra générer une nouvelle paire de clés
	if _, err := os.Stat(privPath); errors.Is(err, os.ErrNotExist) {
		if debugKey {
			fmt.Println("Erreur de Stat dans loadKeyPair")
		}
		return nil, nil, os.ErrNotExist
	}

	// Lecture et décodage de la clé privée (PEM → ECDSA)
	privPem, err := os.ReadFile(privPath)
	if err != nil {
		if debugKey {
			fmt.Println("Erreur de ReadFile dans loadKeyPair")
		}
		return nil, nil, err
	}
	privBlock, _ := pem.Decode(privPem)
	privKey, err := x509.ParseECPrivateKey(privBlock.Bytes)
	if err != nil {
		if debugKey {
			fmt.Println("Erreur de ParseECPPrivateKey dans loadKeyPair")
		}
		return nil, nil, err
	}

	// Lecture et décodage de la clé publique (PEM → ECDSA)
	pubPem, err := os.ReadFile(pubPath)
	if err != nil {
		if debugKey {
			fmt.Println("Erreur de ReadFile dans loadKeyPair")
		}
		return nil, nil, err
	}
	pubBlock, _ := pem.Decode(pubPem)
	pubIfc, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		if debugKey {
			fmt.Println("Erreur de ParsePKIXPublicKey dans loadKeyPair")
		}
		return nil, nil, err
	}
	pubKey := pubIfc.(*ecdsa.PublicKey)

	// Retourne la paire de clés chargée
	return privKey, pubKey, nil
}
