package UI

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// -----------------------------
// Logger
// -----------------------------
// Structure pour afficher les messages dans l'interface utilisateur
// en utilisant un widget RichText de Fyne
type Logger struct {
	View *widget.RichText // composant RichText pour afficher le log
}

// -----------------------------
// NewLogger
// -----------------------------
// Crée et retourne un nouveau Logger
// - Initialise un widget RichText
// - Définit le wrapping sur TextWrapWord pour que le texte soit à la ligne automatiquement
func NewLogger() *Logger {
	rt := widget.NewRichText()
	rt.Wrapping = fyne.TextWrapWord
	return &Logger{View: rt}
}

// -----------------------------
// append (interne)
// -----------------------------
// Ajoute un message au RichText avec une couleur spécifique
// - msg : texte du log
// - color : nom de couleur du thème Fyne (success, warning, error, etc.)
func (l *Logger) append(msg string, color fyne.ThemeColorName) {
	// fyne.Do garantit que l'UI est modifiée dans le thread principal
	fyne.Do(func() {
		// ajoute un nouveau segment de texte au RichText
		l.View.Segments = append(l.View.Segments,
			&widget.TextSegment{
				Text:  msg + "\n",
				Style: widget.RichTextStyle{ColorName: color}, // applique la couleur
			},
		)
		l.View.Refresh() // force le rafraîchissement pour afficher le nouveau texte
	})
}

// -----------------------------
// Fonctions utilitaires pour le log
// -----------------------------
// Simplifie l'ajout de messages colorés selon le type
func (l *Logger) Info(msg string)  { l.append(msg, theme.ColorNameSuccess) } // vert pour info
func (l *Logger) Warn(msg string)  { l.append(msg, theme.ColorNameWarning) } // orange pour avertissement
func (l *Logger) Error(msg string) { l.append(msg, theme.ColorNameError) }   // rouge pour erreur
