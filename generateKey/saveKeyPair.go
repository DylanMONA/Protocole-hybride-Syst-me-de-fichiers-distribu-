package generateKey

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

var debugKey = false

// SaveKeyPair enregistre une paire de clés ECDSA sur le disque.
//
// La clé privée et la clé publique sont sérialisées au format PEM.
// La clé privée est enregistrée avec des permissions restrictives
// afin d’éviter tout accès non autorisé, tandis que la clé publique
// peut être librement lisible.
//
// Paramètres :
//   - priv     : clé privée ECDSA à sauvegarder
//   - pub      : clé publique ECDSA associée
//   - privPath : chemin du fichier de sortie pour la clé privée
//   - pubPath  : chemin du fichier de sortie pour la clé publique
//
// Retour :
//   - error : erreur éventuelle lors de la sérialisation ou de l’écriture des fichiers
func SaveKeyPair(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, privPath, pubPath string) error {

	// ----- Sauvegarde de la clé privée -----
	// Sérialisation de la clé privée au format ASN.1
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		if debugKey {
			fmt.Println("erreur MarshalECPrivateKey")
		}
		return err
	}

	// Encodage PEM de la clé privée
	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	// Écriture de la clé privée sur le disque avec des permissions strictes
	if err := os.WriteFile(privPath, privPem, 0600); err != nil {
		if debugKey {
			fmt.Println("erreur d'écriture sur le disque ")
		}
		return err
	}

	// ----- Sauvegarde de la clé publique -----
	// Sérialisation de la clé publique au format PKIX
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		if debugKey {
			fmt.Println("erreur MarshalPKIXPublicKey ")
		}
		return err
	}

	// Encodage PEM de la clé publique
	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Écriture de la clé publique sur le disque
	return os.WriteFile(pubPath, pubPem, 0644)
}
