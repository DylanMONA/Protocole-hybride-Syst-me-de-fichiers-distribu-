package clientStorage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
)

//
// ======================= CONSTANTES ET TYPES =======================
//

// Identifiants des types de nœuds du Merkle Tree
// Types de noeuds
const (
	// Types de noeuds
	Chunk        = 0
	Directory    = 1
	Big          = 2
	BigDirectory = 3

	// Tailles fixes
	HashSize      = 32
	NameSize      = 32
	DirEntrySize  = NameSize + HashSize // 64
	MaxDirEntries = 16
	MaxBigEntries = 32
	IdSize        = 1
	// Chunks fichiers
	ChunkSize = 1024

	// Permissions fichiers
	FilePerm = 0644
	DirPerm  = 0755
)

//-----------------------------------------------------------------------------------------
// Ce fichier regroupe l’ensemble des fonctions responsables de la construction
// du Merkle Tree à partir de fichiers et de répertoires locaux, en générant
// récursivement les nœuds et les structures intermédiaires nécessaires.

//
// ======================= VARIABLES GLOBALES =======================
//

// Mutex protégeant l’accès concurrent au Merkle Tree
var mu sync.RWMutex

// Map principale contenant tous les nœuds du Merkle Tree (hash → contenu)
var MerkleMap = map[string][]byte{}

// Structure représentant une entrée de répertoire
type DirectoryEntry struct {
	Name string
	Hash []byte
}

// Hash racine du Merkle Tree local
var RootHash []byte

//
// ======================= OUTILS UTILITAIRES =======================
//

// Calcule le hash SHA-256 d’un tableau d’octets
// Paramètre : b → données à hasher
// Retour : hash SHA-256
func Sha(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// Remplit ou tronque un nom pour qu’il fasse exactement 32 octets
// Paramètre : input → nom brut
// Retour : nom paddé
func padTo32(input []byte) []byte {
	out := make([]byte, NameSize)
	copy(out, input)
	return out
}

// Découpe des données en chunks de taille fixe
// Paramètre : data → données du fichier
// Retour : liste de chunks
func SplitIntoChunks(data []byte) [][]byte {
	chunks := make([][]byte, 0, (len(data)+ChunkSize-IdSize)/ChunkSize)
	for i := 0; i < len(data); i += ChunkSize {
		end := i + ChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

// Ajoute un nœud dans la MerkleMap avec comptage de références
// Paramètre : node → nœud à enregistrer
func FillMap(node []byte) {
	if debugMerkle {
		fmt.Println("FillMap")

		fmt.Printf("[DEBUG] Node created: type=%d hash=%x\n", node[0], Sha(node))

	}
	hash := Sha(node)
	key := hex.EncodeToString(hash)

	mu.Lock()
	_, exists := MerkleMap[key]
	if exists {
		CountMap[key]++
	} else {
		MerkleMap[key] = node
		CountMap[key] = 1
	}
	mu.Unlock()
}

// Retourne le type d’un nœud Merkle
// Paramètre : node → nœud à analyser
// Retour : type du nœud
func Typedata(node []byte) byte {
	if node[0] == Chunk {
		return Chunk
	} else if node[0] == Directory {
		return Directory
	} else if node[0] == Big {
		return Big
	} else if node[0] == BigDirectory {
		return BigDirectory
	} else {
		return 255
	}
}

//
// ======================= CONSTRUCTION DES NŒUDS =======================
//

// Construit un nœud Chunk à partir de données
// Paramètre : data → données brutes
// Retour : nœud chunk
func HashChunk(data []byte) []byte {
	return append([]byte{Chunk}, data...)
}

// Construit un nœud Directory à partir d’entrées
// Paramètre : entries → liste des fichiers/répertoires
// Retour : nœud Directory
func HashDirectory(entries []DirectoryEntry) []byte {
	node := []byte{Directory}
	for _, e := range entries {
		node = append(node, padTo32([]byte(e.Name))...)
		node = append(node, Sha(e.Hash)...)
	}
	return node
}

// Construit un nœud Big regroupant plusieurs enfants
// Paramètre : hashes → liste des nœuds enfants
// Retour : nœud Big
func HashBig(hashes [][]byte) []byte {
	node := []byte{Big}
	for _, h := range hashes {
		node = append(node, Sha(h)...)
	}
	return node
}

// Construit un nœud BigDirectory
// Paramètre : hashes → sous-répertoires
// Retour : nœud BigDirectory
func HashBigDirectory(hashes [][]byte) []byte {
	node := []byte{BigDirectory}
	for _, h := range hashes {
		node = append(node, Sha(h)...)
	}
	return node
}

//
// ======================= CONSTRUCTION DU MERKLE TREE =======================
//

// Construit récursivement le Merkle Tree à partir d’un chemin
// Paramètre : path → fichier ou répertoire
// Retour : nœud racine et erreur éventuelle
func BuildMerkleNode(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if debugMerkle {
			fmt.Println("Erreur Stat BuildMerkleNode")
		}
		return nil, err
	}

	if fi.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			if debugMerkle {
				fmt.Println("Erreur ReadDir BuildMerkleNode")
			}
			return nil, err
		}
		var children [][]byte
		for _, e := range entries {
			childPath := path + "/" + e.Name()
			childNode, err := BuildMerkleNode(childPath)
			if err != nil {
				return nil, err
			}
			children = append(children, childNode)
		}
		node := buildDirectoryNode(entries, children)
		return node, nil
	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			if debugMerkle {
				fmt.Println("Erreur ReadFile BuildMerkleNode")
			}
			return nil, err
		}
		chunks := SplitIntoChunks(data)
		var children [][]byte
		for _, c := range chunks {
			chunkNode := HashChunk(c)
			FillMap(chunkNode)
			children = append(children, chunkNode)
		}
		for len(children) > 1 {
			children = buildBigNodes(children)
		}
		FillMap(children[0])
		return children[0], nil
	}
}

// -----------------------------------------------------------------------------------------
// Construit un nœud de type Directory ou BigDirectory selon le nombre d’entrées.
// Si le nombre d’entrées dépasse MaxDirEntries, plusieurs sous-nœuds sont créés
// puis regroupés dans un BigDirectory.
// Paramètres :
//   - entries : liste des entrées du répertoire (fichiers / sous-répertoires)
//   - children : liste des nœuds enfants déjà construits
//
// Retour :
//   - le nœud Merkle représentant le répertoire
func buildDirectoryNode(entries []os.DirEntry, children [][]byte) []byte {
	dirEntries := make([]DirectoryEntry, len(entries))
	for i, e := range entries {
		dirEntries[i] = DirectoryEntry{
			Name: e.Name(),
			Hash: children[i],
		}
	}
	var node []byte
	if len(dirEntries) <= MaxDirEntries {
		node = HashDirectory(dirEntries)
		FillMap(node)
	} else {
		var chunkHashes [][]byte
		for i := 0; i < len(dirEntries); i += MaxDirEntries {
			end := i + MaxDirEntries
			if end > len(dirEntries) {
				end = len(dirEntries)
			}
			subNode := HashDirectory(dirEntries[i:end])
			FillMap(subNode)
			chunkHashes = append(chunkHashes, subNode)
		}
		for len(chunkHashes) > 1 {
			chunkHashes = buildBigDirectoryNodes(chunkHashes)
		}
		node = chunkHashes[0]
	}
	return node
}

// -----------------------------------------------------------------------------------------
// Regroupe des nœuds enfants en nœuds intermédiaires de type Big.
// Utilisé pour gérer les fichiers volumineux.
// Paramètre :
//   - children : liste de nœuds enfants
//
// Retour :
//   - liste de nœuds Big
func buildBigNodes(children [][]byte) [][]byte {
	return mergeNodes(children, Big)
}

// -----------------------------------------------------------------------------------------
// Regroupe des nœuds Directory en nœuds intermédiaires BigDirectory.
// Utilisé lorsque le nombre d’entrées d’un répertoire est trop élevé.
// Paramètre :
//   - children : liste de nœuds Directory
//
// Retour :
//   - liste de nœuds BigDirectory
func buildBigDirectoryNodes(children [][]byte) [][]byte {
	return mergeNodes(children, BigDirectory)
}

// -----------------------------------------------------------------------------------------
// Fusionne une liste de nœuds enfants en nœuds intermédiaires.
// Les enfants sont regroupés par blocs de taille MaxBigEntries.
// Paramètres :
//   - children : liste de nœuds à regrouper
//   - nodeType : type du nœud résultant (Big ou BigDirectory)
//
// Retour :
//   - liste des nouveaux nœuds intermédiaires
func mergeNodes(children [][]byte, nodeType byte) [][]byte {

	var next [][]byte
	for i := 0; i < len(children); i += MaxBigEntries {
		end := i + MaxBigEntries
		if end > len(children) {
			end = len(children)
		}
		node := []byte{nodeType}
		for _, h := range children[i:end] {
			node = append(node, Sha(h)...)
		}
		FillMap(node)
		next = append(next, node)
	}
	return next
}
