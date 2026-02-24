package clientStorage

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

//-----------------------------------------------------------------------------------------
// Ce fichier contient les structures et fonctions dédiées au stockage en mémoire,
// à la gestion, à la vérification d’intégrité et à la suppression des nœuds
// du Merkle Tree une fois celui-ci construit.

//
// ======================= VARIABLES GLOBALES =======================
//

// Compteur de références pour chaque nœud (permet la suppression sécurisée)
var CountMap = map[string]uint{}

var debugMerkle = false

// -----------------------------------------------------------------------------------------
// Recherche un nœud Merkle à partir de son hash.
// Paramètre :
//   - hash : hash SHA-256 du nœud recherché
//
// Retour :
//   - le nœud correspondant
//   - un booléen indiquant si le nœud existe
func FindHash(hash []byte) ([]byte, bool) {
	mu.Lock()
	node, exiting := MerkleMap[hex.EncodeToString(hash)]
	mu.Unlock()
	return node, exiting
}

// -----------------------------------------------------------------------------------------
// Recherche un fichier ou répertoire par son nom dans l’ensemble du Merkle Tree.
// Paramètre :
//   - name : nom recherché (en bytes)
//
// Retour :
//   - le hash du nœud correspondant
//   - un booléen indiquant si le nom a été trouvé
func FindName(name []byte) ([]byte, bool) {
	if debugMerkle {
		fmt.Println("FindName")
	}
	for _, node := range MerkleMap {
		if Typedata(node) == Directory {
			offset := 1
			for offset+DirEntrySize <= len(node) {
				nameBytes := node[offset : offset+NameSize]
				hashBytes := node[offset+NameSize : offset+DirEntrySize]
				offset += DirEntrySize
				if bytes.Equal(bytes.TrimRight(nameBytes, "\x00"), name) {
					return hashBytes, true
				}
			}
		}
	}
	if debugMerkle {
		fmt.Println("Non trouvé")
	}
	return nil, false
}

// -----------------------------------------------------------------------------------------
// Affiche récursivement le Merkle Tree à partir d’un nœud donné.
// Utilisé uniquement pour le débogage.
// Paramètres :
//   - node : nœud courant
//   - depth : profondeur dans l’arbre (indentation)
func PrintTree(node []byte, depth int) {
	prefix := strings.Repeat("  ", depth)
	if len(node) == 0 {
		fmt.Printf("%s<empty node>\n", prefix)
		return
	}
	switch node[0] {
	case Chunk:
	case Directory:
		fmt.Printf("%sDirectory:\n", prefix)
		offset := 1
		for offset+DirEntrySize <= len(node) {
			nameBytes := node[offset : offset+NameSize]
			hashBytes := node[offset+NameSize : offset+DirEntrySize]
			offset += DirEntrySize
			fmt.Printf("%s  Name: %s\n", prefix, strings.TrimRight(string(nameBytes), "\x00"))
			child, ok := MerkleMap[hex.EncodeToString(hashBytes)]
			if ok {
				PrintTree(child, depth+1)
			}
		}
	case Big, BigDirectory:
		offset := 1
		for offset+HashSize <= len(node) {
			childHash := node[offset : offset+HashSize]
			offset += HashSize
			child, ok := MerkleMap[hex.EncodeToString(childHash)]
			if ok {
				PrintTree(child, depth+1)
			}
		}
	default:
		fmt.Printf("%sUnknown node type %d\n", prefix, node[0])
	}
}

// -----------------------------------------------------------------------------------------
// Vérifie l’intégrité complète d’un Merkle Tree à partir de la racine.
// Paramètre :
//   - rootHash : hash de la racine
//
// Retour :
//   - true si l’arbre est valide, false sinon
func VerifyMerkle(rootHash []byte) bool {
	if debugMerkle {
		fmt.Println("VerifyMerkle")
	}
	visited := make(map[string]bool)
	mu.RLock()
	ok := verifyNode(rootHash, visited)
	mu.RUnlock()
	return ok
}

// -----------------------------------------------------------------------------------------
// Vérifie récursivement un nœud et ses enfants.
// Paramètres :
//   - hash : hash du nœud à vérifier
//   - visited : map pour éviter les boucles
//
// Retour :
//   - true si le sous-arbre est valide
func verifyNode(hash []byte, visited map[string]bool) bool {
	key := hex.EncodeToString(hash)

	if visited[key] {
		return true
	}
	visited[key] = true

	node, exists := MerkleMap[key]
	if !exists {
		return false
	}

	if len(node) == 0 {
		return true
	}

	switch node[0] {
	case Chunk:
		return true
	case Directory:
		count := (len(node) - IdSize) / DirEntrySize
		for i := 0; i < count; i++ {
			childHash := node[IdSize+i*DirEntrySize+NameSize : IdSize+i*DirEntrySize+DirEntrySize]
			if !verifyNode(childHash, visited) {
				return false
			}
		}
		return true
	case Big, BigDirectory:
		count := (len(node) - IdSize) / HashSize
		for i := 0; i < count; i++ {
			childHash := node[IdSize+i*HashSize : IdSize+i*HashSize+HashSize]
			if !verifyNode(childHash, visited) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// -----------------------------------------------------------------------------------------
// Supprime un Merkle Tree à partir de la racine en tenant compte des références.
// Paramètre :
//   - rootHash : hash de la racine à supprimer
func DeleteMerkleTree(rootHash []byte) {
	visited := make(map[string]bool)
	deleteNode(rootHash, visited)
}

// -----------------------------------------------------------------------------------------
// Supprime récursivement un nœud et ses enfants si plus aucune référence n’existe.
// Paramètres :
//   - hash : hash du nœud à supprimer
//   - visited : map pour éviter les suppressions multiples
func deleteNode(hash []byte, visited map[string]bool) {
	key := hex.EncodeToString(hash)

	if visited[key] {
		return
	}
	visited[key] = true

	mu.Lock()
	node, exists := MerkleMap[key]
	if !exists {
		mu.Unlock()
		return
	}

	CountMap[key]--
	if CountMap[key] > 0 {
		mu.Unlock()
		return
	}
	mu.Unlock()

	switch node[0] {
	case Directory:
		count := (len(node) - IdSize) / DirEntrySize
		for i := 0; i < count; i++ {
			childHash := node[IdSize+i*DirEntrySize+NameSize : IdSize+i*DirEntrySize+DirEntrySize]
			deleteNode(childHash, visited)
		}
	case Big, BigDirectory:
		count := (len(node) - IdSize) / HashSize
		for i := 0; i < count; i++ {
			childHash := node[IdSize+i*HashSize : IdSize+i*HashSize+HashSize]
			deleteNode(childHash, visited)
		}
	}

	mu.Lock()
	delete(MerkleMap, key)
	delete(CountMap, key)
	mu.Unlock()
}

// -----------------------------------------------------------------------------------------
// Retourne la liste des hashes enfants d’un nœud Merkle.
// Paramètre :
//   - node : nœud dont on veut les enfants
//
// Retour :
//   - liste de hashes hexadécimaux
func ListChildrenHashes(node []byte) []string {
	children := []string{}
	switch node[0] {
	case Directory:
		count := (len(node) - 1) / 64
		for i := 0; i < count; i++ {
			childHash := node[1+i*64+32 : 1+i*64+64]
			children = append(children, hex.EncodeToString(childHash))
		}
	case BigDirectory, Big:
		count := (len(node) - 1) / 32
		for i := 0; i < count; i++ {
			childHash := node[1+i*32 : 1+i*32+32]
			children = append(children, hex.EncodeToString(childHash))
		}
	}
	return children
}
