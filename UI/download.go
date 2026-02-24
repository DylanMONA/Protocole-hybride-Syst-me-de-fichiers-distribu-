package UI

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"myp2p/client"
	"myp2p/clientStorage"

	"fyne.io/fyne/v2/widget"
)

// -----------------------------
// Constantes de répertoire
// -----------------------------
const OUTPUT_DIRECTORY = "OUTPUT" // Répertoire principal où les fichiers téléchargés seront stockés

var DATA_DIRECTORY = "./OurData" // Répertoire local où les données brutes sont stockées

// -----------------------------
// DownloadFileGUI
// -----------------------------
// Fonction pour télécharger/reconstruire un fichier depuis un hash donné
// et le sauvegarder dans l'interface utilisateur (ou filesystem) avec un logger.
//
// Paramètres :
// - hash : hash du noeud ou fichier dans le réseau P2P
// - filename : nom du fichier final (optionnel)
// - peerName : nom du peer source, utilisé pour créer un sous-répertoire
// - log : Logger pour afficher les messages d'info ou d'erreur
// - version : version du fichier (utilisé pour nommer le fichier si différent de la dernière version)
func DownloadFileGUI(
	hash []byte,
	filename string,
	peerName string,
	log Logger,
	version string,
) {

	// Crée le chemin complet pour stocker le fichier :
	// OUTPUT/<PeerName>/<filename>
	path := filepath.Join(OUTPUT_DIRECTORY, peerName)

	if filename != "" {
		filename = clientStorage.UniqueName(OUTPUT_DIRECTORY+"/"+peerName, filename)
		path = filepath.Join(path, filename)
	}
	if version != LATEST_VERSION {
		versionName := clientStorage.UniqueName(OUTPUT_DIRECTORY+"/"+peerName, version)
		path = filepath.Join(path, versionName)
	}

	// Crée tous les dossiers intermédiaires si nécessaire
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		log.Error(err.Error()) // log de l'erreur
		return
	}

	// Sauvegarde du temps de début pour mesurer la durée
	start := time.Now()

	// Reconstruit le fichier à partir du hash via clientStorage
	if err := clientStorage.RebuildNode(hash, path); err != nil {
		log.Error(err.Error()) // log si reconstruction échoue
		return
	}

	// Log de succès avec durée du téléchargement
	log.Info(fmt.Sprintf(
		"Téléchargement terminé (%s)",
		time.Since(start).Round(time.Millisecond),
	))
}

// -----------------------------
// RestoreMyFile
// -----------------------------
// Restore jusqu'a maximun mes 2 dernier fichier
// version a 3 possibilité current, last, previous
// current = fichier actuel
// last = dernier fichier
// previuous = l'avant dernier fichier
func RestoreMyFile(peerChecks *widget.CheckGroup, conn *net.UDPConn, priv *ecdsa.PrivateKey, logger *Logger, version string) {

	switch version {
	case LATEST_VERSION:
		// Supprime le fichier
		if err := os.RemoveAll(DATA_DIRECTORY); err != nil {
			logger.Error("Erreur suppression du répertoire: " + err.Error())
			return
		}
		// Reconstruit le fichier
		if err := clientStorage.RebuildNode(clientStorage.RootHash, DATA_DIRECTORY); err != nil {
			logger.Error(err.Error()) // log si reconstruction échoue
			return
		}
		return
	case PREVIOUS_VERSION:

		if len(client.MyListroots) > 1 && client.MyListroots[1] != nil {
			// Supprime le fichier
			if err := os.RemoveAll(DATA_DIRECTORY); err != nil {
				logger.Error("Erreur suppression du répertoire: " + err.Error())
				return
			}
			if len(client.MyListroots) > 2 {
				// Reconstruit le fichier
				if err := clientStorage.RebuildNode(client.MyListroots[1], DATA_DIRECTORY); err != nil {
					logger.Error(err.Error()) // log si reconstruction échoue
					return
				}
			} else {

				// Reconstruit le fichier
				if err := clientStorage.RebuildNode(client.MyListroots[0], DATA_DIRECTORY); err != nil {
					logger.Error(err.Error()) // log si reconstruction échoue
					return
				}
			}
		} else {

			logger.Warn("Vous n'avez pas d'ancien merkle ")
		}
		return
	case SECOND_LAST_VERSION:
		if len(client.MyListroots) > 2 && client.MyListroots[0] != nil {
			// Supprime le fichier
			if err := os.RemoveAll(DATA_DIRECTORY); err != nil {
				logger.Error("Erreur suppression du répertoire: " + err.Error())
				return
			}
			// Reconstruit le fichier
			if err := clientStorage.RebuildNode(client.MyListroots[0], DATA_DIRECTORY); err != nil {
				logger.Error(err.Error()) // log si reconstruction échoue
				return
			}

		} else {

			logger.Warn("Vous n'avez pas d'ancien merkle ")
		}
		return

	}

}
