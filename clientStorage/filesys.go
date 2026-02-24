package clientStorage

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ---------------------
// Configuration debug
// ---------------------

// Active l’affichage des informations de débogage
var debug = true

// ---------------------
// Reconstruction Merkle
// ---------------------

// RebuildNode reconstruit récursivement un fichier ou un répertoire
// à partir de son hash Merkle.
//
// Paramètres :
//   - hash : hash du nœud Merkle à reconstruire
//   - path : chemin local où reconstruire le nœud
//
// Retour :
//   - erreur éventuelle lors de la reconstruction
func RebuildNode(hash []byte, path string) error {
	node, ok := MerkleMap[hex.EncodeToString(hash)]

	if debug {
		fmt.Println("\n\n=== Reconstruction du noeud :", hex.EncodeToString(hash), "===")
		fmt.Println("Noeud Merkle :", node)
	}

	if !ok {
		return fmt.Errorf("node not found: %x", hash)
	}

	// Nœud vide : rien à reconstruire
	if len(node) == 0 {
		fmt.Printf("%s <empty node>\n", path)
		return nil
	}

	switch node[0] {

	// ---------------------
	// Chunk : feuille → écriture directe
	// ---------------------
	case Chunk:
		return os.WriteFile(path, node[IdSize:], FilePerm)

	// ---------------------
	// Directory : création du dossier et reconstruction récursive
	// ---------------------
	case Directory:
		if err := os.MkdirAll(path, DirPerm); err != nil {
			return err
		}

		count := (len(node) - IdSize) / DirEntrySize
		for i := 0; i < count; i++ {
			nameBytes := node[IdSize+i*DirEntrySize : IdSize+i*DirEntrySize+NameSize]
			childHash := node[IdSize+i*DirEntrySize+NameSize : IdSize+i*DirEntrySize+DirEntrySize]

			name := string(bytes.TrimRight(nameBytes, "\x00"))
			Thename := UniqueName(path, name)
			childPath := filepath.Join(path, Thename)

			if err := RebuildNode(childHash, childPath); err != nil {
				return err
			}
		}
		return nil

	// ---------------------
	// Big : fichier composé de chunks ou de Big imbriqués
	// ---------------------
	case Big:
		f, err := os.Create(path)
		if err != nil {
			fmt.Println("Erreur création fichier Big :", err)
			return err
		}
		defer f.Close()

		count := (len(node) - IdSize) / HashSize
		for i := 0; i < count; i++ {
			childHash := node[IdSize+i*HashSize : IdSize+i*HashSize+HashSize]
			childNode := MerkleMap[hex.EncodeToString(childHash)]

			if childNode[0] != Chunk {
				if err := WriteBigToFile(f, childNode); err != nil {
					return err
				}
				continue
			}

			if _, err := f.Write(childNode[IdSize:]); err != nil {
				fmt.Println("Erreur écriture chunk :", err)
				return err
			}
		}
		return nil

	// ---------------------
	// BigDirectory : regroupement de répertoires
	// ---------------------
	case BigDirectory:
		count := (len(node) - IdSize) / HashSize
		for i := 0; i < count; i++ {
			childHash := node[IdSize+i*HashSize : IdSize+i*HashSize+HashSize]
			if err := RebuildNode(childHash, path); err != nil {
				return err
			}
		}
		return nil

	// ---------------------
	// Type inconnu
	// ---------------------
	default:
		return fmt.Errorf("unknown node type")
	}
}

// ---------------------
// Écriture récursive Big
// ---------------------

// WriteBigToFile écrit récursivement le contenu d’un nœud Big dans un fichier.
//
// Paramètres :
//   - f    : fichier ouvert en écriture
//   - node : nœud Big à écrire
//
// Retour :
//   - erreur éventuelle
func WriteBigToFile(f *os.File, node []byte) error {
	count := (len(node) - IdSize) / HashSize

	for i := 0; i < count; i++ {
		childHash := node[IdSize+i*HashSize : IdSize+i*HashSize+HashSize]
		childNode := MerkleMap[hex.EncodeToString(childHash)]

		switch childNode[0] {

		case Chunk:
			if _, err := f.Write(childNode[IdSize:]); err != nil {
				return err
			}

		case Big:
			// Récursion sur Big imbriqué
			if err := WriteBigToFile(f, childNode); err != nil {
				return err
			}

		default:
			return fmt.Errorf("invalid child in Big: %d", childNode[0])
		}
	}
	return nil
}

// ---------------------
// Téléchargement simple
// ---------------------

// DownloadFile supprime le chemin cible puis reconstruit
// entièrement le fichier ou répertoire depuis le Merkle Tree.
//
// Paramètres :
//   - hash : hash racine du fichier à télécharger
//   - path : chemin de destination
func DownloadFile(hash []byte, path string) {
	// Suppression complète pour éviter les incohérences
	_ = os.RemoveAll(path)

	if err := RebuildNode(hash, path); err != nil {
		fmt.Println("Erreur lors de la reconstruction :", err)
		return
	}

	fmt.Println("Fichier téléchargé avec succès")
}

// UniqueName génère un nom de fichier unique dans le répertoire donné.
// Si le nom existe déjà, il ajoute un suffixe numérique avant l'extension.
//
// Paramètres :
//   - dir  : répertoire où vérifier l'unicité
//   - name : nom de fichier souhaité
//
// Retour :
//   - nom de fichier unique
func UniqueName(dir string, name string) string {

	extension := filepath.Ext(name)
	baseName := strings.TrimSuffix(name, extension)

	counter := 1
	for {

		currentPath := filepath.Join(dir, name)
		_, err := os.Stat(currentPath)

		if os.IsNotExist(err) {
			return name
		}

		newName := fmt.Sprintf("%s(%d)%s", baseName, counter, extension)
		name = newName
		counter++
	}
}
