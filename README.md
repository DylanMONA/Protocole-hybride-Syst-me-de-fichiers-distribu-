# Projet de Programmation Internet

![Go](https://img.shields.io/badge/Go-1.21-blue?logo=go\&logoColor=white)
![Fyne](https://img.shields.io/badge/Fyne-2.x-ff69b4)

**Auteurs :** Barkan Ines, Dylan Mona

---

## 1. Présentation générale

Ce projet implémente un **système de fichiers distribué en lecture seule** dans lequel chaque pair partage un arbre de fichiers local accessible par les autres pairs. Les arbres de fichiers peuvent évoluer dynamiquement, mais **aucun pair ne peut modifier les données d’un autre pair**.

L’architecture est **hybride** :

* Un **serveur central REST** agit comme point de rendez-vous et distribue les clés publiques cryptographiques.
* Les **transferts de données** s’effectuent directement entre pairs via le protocole **UDP**.

Chaque pair est identifié de manière unique et utilise des mécanismes cryptographiques pour garantir :

* La sécurité des communications avec le serveur central (HTTPS).
* L’intégrité des données grâce aux **arbres de Merkle**.
* L’authentification et l’intégrité des messages échangés entre pairs via des **signatures numériques**.

---

## 2. Fonctionnalités principales

### Client – Serveur

* Enregistrement auprès du serveur central
* Récupération de la liste des pairs connectés et de leurs clés publiques

### Pair à Pair (P2P)

* Communication directe entre pairs via UDP
* Transfert de données basé sur les arbres de Merkle
* Signature et vérification cryptographique des paquets
* Support du NAT traversal pour les pairs derrière un NAT

### Gestion des fichiers

* Partage des fichiers locaux via le répertoire `OurData/`
* Téléchargement des fichiers distants dans le répertoire `OUTPUT/`
* Support des fichiers volumineux et des arborescences profondes

### Interface Graphique (GUI)

* Visualisation des pairs connectés
* Navigation dans les arbres de fichiers partagés
* Téléchargement interactif des fichiers
* Visualisation et inspection des arbres de Merkle
* Journalisation en temps réel des événements et erreurs

---

## 3. Installation

### Prérequis

* **Go 1.21** ou version ultérieure
* Un système compatible avec Fyne (Linux, macOS, Windows)

### Dépendances

Installation de la bibliothèque graphique Fyne :

```bash
go get fyne.io/fyne/v2
```

---

## 4. Structure du projet

```text
project-root/
│
├─ client/
│   ├─ transaction.go         # Gestion des transactions entre pairs
│   ├─ crypto.go              # Fonctions cryptographiques
│   ├─ peer.go                # Structure et gestion des pairs
│   ├─ requestHandler.go      # Gestion des requêtes entrantes
│   ├─ responseHandler.go     # Gestion des réponses entrantes
│   ├─ datum.go               # Gestion des unités de données
│   ├─ dispatcher.go          # Distribution des messages
│   ├─ events.go              # Gestion des événements internes
│   ├─ parsePacket.go         # Analyse des paquets UDP
│   ├─ sendAndBuildPacket.go  # Construction et envoi des paquets
│   ├─ maintenance.go         # Maintenance du client et ping des pairs
│   ├─ sliding_window.go      # Fenêtre glissante pour le transfert
│   └─ serveur_api.go         # Interaction avec le serveur central
│   └─ extension.go           # Gestion des extensions (Hello/HelloReply)
│
├─ clientStorage/
│   ├─ merkle.go              # Implémentation de l’arbre de Merkle
│   └─ filesys.go             # Abstraction du système de fichiers local
│
├─ generateKey/
│   ├─ loadKeyPair.go         # Chargement des paires de clés ECDSA
│   └─ saveKeyPair.go         # Sauvegarde des paires de clés ECDSA
|
├─ OtherPeerDatum/            # Données pour un deuxième peer dans le but d'une démonstration
├─ OurData/                   # Fichiers partagés par notre pair (En d'autres termes ce sont nos fichiers)
├─ OUTPUT/                    # Fichiers téléchargés depuis d’autres pairs (Ce qu'on a téléchargé)
│
├─ UI/
│   ├─ dataActions.go         # Actions sur les données via l’interface
│   ├─ gui.go                 # Initialisation et gestion de l’interface graphique
│   ├─ logs.go                # Système de logs dans l’interface
│   ├─ download.go            # Interface de téléchargement
│   ├─ merkleActions.go       # Actions GUI liées aux arbres de Merkle
│   ├─ PeersActions.go        # Actions GUI liées aux pairs
│   └─ PeersUI.go             # Affichage des pairs dans l’interface
│
└─ main.go                    # Point d’entrée principal de l’application
```

---

## 5. Utilisation

### Lancement du projet

```bash
go run main.go
```
ou

```bash
go build -o myproject main.go
./myproject
```

### Interface graphique

L’interface permet de :

* Visualiser les pairs connectés
* Parcourir les fichiers partagés
* Télécharger des fichiers depuis d’autres pairs
* Inspecter les arbres de Merkle
* Consulter les journaux d’événements et d’erreurs

Pour le mode d'utilisation, voir la section 10.2 du rapport.
---

## 6. Sécurité

* Utilisation de **paires de clés ECDSA** pour l’identification et la signature des messages
* Vérification de l’intégrité des données via les **arbres de Merkle**
* Communications sécurisées avec le serveur central via **HTTPS**
* Système strictement **en lecture seule**, empêchant toute modification distante

---

## 7. Extensions possibles

* Téléchargements parallèles avec contrôle de congestion
* Streaming de fichiers multimédias (ex. vidéos)
* Chiffrement de bout en bout avec forward secrecy
* Extensions personnalisées du protocole UDP

---

## 8. Crédits

* **Auteurs :** Barkan Ines, Dylan Mona
* Primitives cryptographiques fournies par la bibliothèque standard Go (ECDSA)

Aucune aide externe ou outil d’IA n’a été utilisé pour le développement de ce projet, sauf mention explicite dans le rapport PDF associé.
