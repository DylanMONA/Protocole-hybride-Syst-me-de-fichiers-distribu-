package UI

import (
	"time"

	"myp2p/client"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

// ------------------------------------------------------
// Debug mode pour afficher des logs supplémentaires
// ------------------------------------------------------
var Debug = false

// ------------------------------------------------------
// buildPeerSelector
// ------------------------------------------------------
// Construit un widget CheckGroup (checkbox) pour sélectionner des peers
// - update: fonction interne qui récupère les noms de tous les peers connus
// - crée un CheckGroup horizontal avec tous les noms de peers
// - lance un goroutine autoRefreshPeers pour mettre à jour périodiquement la liste des peers
func buildPeerSelector(log Logger) *widget.CheckGroup {
	update := func() []string {
		client.PeersMu.Lock()
		names := make([]string, 0, len(client.Peers))
		for name := range client.Peers {
			names = append(names, name)
		}
		client.PeersMu.Unlock()
		return names
	}

	checks := widget.NewCheckGroup(update(), func([]string) {})
	checks.Horizontal = true

	// rafraîchissement automatique toutes les 20 secondes
	go autoRefreshPeers(checks, update, log)

	return checks
}

// ------------------------------------------------------
// getSinglePeer
// ------------------------------------------------------
// Récupère un peer à partir d'un CheckGroup en s'assurant qu'un seul peer est sélectionné
// - Vérifie que la sélection n’est pas vide et qu’un seul peer est sélectionné
// - Retourne le peer correspondant et un bool pour indiquer la validité
func getSinglePeer(
	checks *widget.CheckGroup,
	log Logger,
) (*client.Peer, bool) {

	if len(checks.Selected) == 0 {
		log.Warn("Sélectionnez un peer")
		return nil, false
	}
	if len(checks.Selected) > 1 {
		log.Warn("Sélectionnez un seul peer")
		return nil, false
	}

	peer, ok := client.FindPeer(checks.Selected[0])
	if !ok {
		log.Error("Peer introuvable")
		return nil, false
	}
	return peer, true
}

// ------------------------------------------------------
// autoRefreshPeers
// ------------------------------------------------------
// Rafraîchit automatiquement le CheckGroup avec la liste des peers connus
// - ticker: toutes les 30 secondes
// - client.GetPeerListIfChanged(): récupère la liste de peers si elle a changé
// - client.RefreshPeers(): met à jour la map des peers connus côté client
// - Met à jour le CheckGroup (Options et Selected)
// - Fait tout dans fyne.Do pour exécuter dans le thread UI
func autoRefreshPeers(
	checks *widget.CheckGroup,
	update func() []string,
	log Logger,
) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		fyne.Do(func() {
			names, changed, err := client.GetPeerListIfChanged()
			if err != nil {
				log.Warn("Erreur refresh peers")
				return
			}
			if changed {
				client.RefreshPeers(names)
				if Debug {
					log.Info("Peers mis à jour")
				}
			}
			// Met à jour la liste visible dans le CheckGroup
			checks.Options = update()
			checks.Refresh()
		})
	}
}
