package client

import (
	"fmt"
	"sync"
	"time"
)

var debugSlidingWindow = true

type SlidingWindow struct {
	mu       sync.RWMutex
	Size     int //combien de DatumRequest je peux avoir en vol
	Min      int // min de la taille de la fenetre
	Max      int // max de la taille de la fenetre
	InFlight int //combien sont actuellement en vol
}

func NewSlidingWindow(min, initial, max int) SlidingWindow {
	if initial < min {
		initial = min
	}
	return SlidingWindow{
		Size: initial,
		Min:  min,
		Max:  max,
	}
}

// appelé AVANT d'envoyer un DatumRequest pour savoir si l'envoie est possible
func (w *SlidingWindow) CanSend() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	ok := w.InFlight < w.Size
	if ok {
		fmt.Println("oui on peut envoyer")
	} else {
		fmt.Println("non on peut pas")
	}
	return ok
}

// appelé Lorsque l'on a envoyé un DatumRequest
func (w *SlidingWindow) OnSend() {
	w.mu.Lock()
	w.InFlight++
	if w.InFlight > w.Size {
		fmt.Println("[BUG] InFlight > Size, correction")
		w.InFlight = w.Size
	}
	w.mu.Unlock()
}

// appelé quand un Datum arrive correctement

func (w *SlidingWindow) OnSuccess(rtt time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.InFlight > 0 {
		if debugSlidingWindow {
			fmt.Println("décrémenter")
		}
		w.InFlight--
	}

	if w.Size < w.Max {
		if debugSlidingWindow {
			fmt.Println("Augmentation de la taille de la fenêtre")
		}
		w.Size++
	} else {
		if debugSlidingWindow {
			fmt.Println("Max atteint", w.Max)
		}
	}
}

// appelé sur timeout / retry épuisé
func (w *SlidingWindow) OnTimeout() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.InFlight > 0 {
		if debugSlidingWindow {
			fmt.Println("timeout décrémenter")
		}
		w.InFlight--
	}

	if w.Size > w.Min {
		w.Size /= 2
		if w.Size < w.Min {
			w.Size = w.Min
		}
	}
}

// Pour debug
func (w *SlidingWindow) dump(reason string) {
	fmt.Printf(
		"[WIN][%s] Size=%d InFlight=%d\n",
		reason,
		w.Size,
		w.InFlight,
	)
}
