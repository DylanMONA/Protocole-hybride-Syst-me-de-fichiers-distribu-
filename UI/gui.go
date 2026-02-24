package UI

import (
	"crypto/ecdsa"
	"net"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func StartGUI(conn *net.UDPConn, priv *ecdsa.PrivateKey) {

	app := app.New()
	win := app.NewWindow("P2P GUI")

	logger := NewLogger()

	// initialiser les events
	RegisterCallbacks(logger)

	// lancer refresh et initialiser la première liste de peers
	peerChecks := buildPeerSelector(*logger)

	// créer les bouton

	// update mon merkle
	myMerkleBtn := widget.NewButton("UPDATE MY MERKLE", func() {
		UpdateMyMerkle(logger)
	})

	banBtn := widget.NewButton("BAN PEER SELECTED", func() {
		BanSelectedPeers(peerChecks, logger)
	})

	unbanBtn := widget.NewButton("UNBAN PEER SELECTED", func() {
		UnbanSelectedPeers(peerChecks, logger)
	})

	handshakeBtn := widget.NewButton("HANDSHAKE SELECTED", func() {
		HandshakeSelectedPeers(peerChecks, conn, priv, logger)
	})

	handshakeAllBtn := widget.NewButton("HANDSHAKE ALL", func() {
		HandshakeAllPeers(conn, priv, logger)
	})

	askRootBtn := widget.NewButton("ASK ROOT", func() {
		AskRootSelectedPeers(peerChecks, conn, priv, logger)
	})

	askMerkleBtn := widget.NewButton("ASK MERKLE", func() {
		AskMerkleSelectedPeers(peerChecks, conn, priv, logger)
	})

	restoreLatestBtn := widget.NewButton("LATEST MERKLE", func() {
		RestoreMyFile(peerChecks, conn, priv, logger, LATEST_VERSION)
	})

	restorePreviousBtn := widget.NewButton("PREVIOUS MERKLE", func() {
		RestoreMyFile(peerChecks, conn, priv, logger, PREVIOUS_VERSION)
	})

	restoreEarlierBtn := widget.NewButton("EARLIER MERKLE", func() {
		RestoreMyFile(peerChecks, conn, priv, logger, SECOND_LAST_VERSION)
	})

	restoreSplit := container.NewGridWithColumns(3,
		restoreLatestBtn,
		restorePreviousBtn,
		restoreEarlierBtn,
	)

	// DATA

	askDataMode := widget.NewSelect([]string{
		LATEST_VERSION,
		PREVIOUS_VERSION,
		SECOND_LAST_VERSION,
	}, func(selected string) {})
	askDataMode.SetSelected(LATEST_VERSION)

	fileEntry := widget.NewEntry()
	fileEntry.SetPlaceHolder("Nom du fichier (vide = tout)")

	askDataBtn := widget.NewButton("ASK DATA", func() {
		filename := fileEntry.Text
		version := askDataMode.Selected
		AskDataPeer(peerChecks, filename, version, logger)
	})

	// Afficher l'arbre ( pour le debogage)

	merkleBtn := widget.NewButton("PRINT MERKLE TREE", func() {

		peer, ok := getSinglePeer(peerChecks, *logger)
		if !ok {
			return
		}

		PrintPeerMerkle(peer, *logger)
	})

	/* ================= LAYOUT ================= */

	buttonsTop := container.NewGridWithColumns(4,
		myMerkleBtn,
		banBtn,
		unbanBtn,
		handshakeBtn,
		handshakeAllBtn,
		askRootBtn,
		askMerkleBtn,
	)
	// mettre le CheckGroup dans un conteneur scroll horizontal
	scrollPeerChecks := container.NewHScroll(peerChecks)
	scrollPeerChecks.SetMinSize(fyne.NewSize(400, 50)) // largeur et hauteur mini

	top := container.NewVBox(
		widget.NewLabel("Peers :"),
		scrollPeerChecks,
		buttonsTop,
		askDataMode, //à ajouter
		widget.NewSeparator(),
		widget.NewLabel("ASK DATA :"),
		fileEntry,
		askDataBtn,
		widget.NewSeparator(),
		merkleBtn,
		restoreSplit,
	)

	logContainer := container.NewVScroll(logger.View)
	logContainer.SetMinSize(fyne.NewSize(0, 300))

	content := container.NewBorder(nil, logContainer, nil, nil, top)

	win.SetContent(content)
	win.Resize(fyne.NewSize(700, 650))
	logger.Info("Application démarrée")
	win.ShowAndRun()
}
