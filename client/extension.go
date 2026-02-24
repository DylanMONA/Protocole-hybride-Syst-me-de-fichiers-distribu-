package client

import "fmt"

// Constantes qui délimitent le bit d'une extension donnée
const (
	ExtensionNat         = 0 // bit 0
	ExtensionChiffrement = 1 // bit 1
)

// -----------------------------------------------------------------------------------------------------
// Pour débuger l'extension
var debugExtension = false

// -----------------------------------------------------------------------------------------------------
// BuildExtension génère le uint32 prêt à être utilisé
func BuildExtension() uint32 {
	var ext uint32 = 0
	//  on mets toujours à 1 l'extension du Nat
	ext |= 1 << ExtensionNat

	// si c'est chiffré alors extension comporte 0000 0000 0000 0000 0000 0000 0000 0011
	// 00 00 00 03 en base 16 (on fait des paquets de 4 car 16 = 2^4)

	// le ou logique permet l'addition =>  1 | 0 => 1,  1 | 1 reste inchangé, ça permet de mettre un seul bit à 1
	// exemple : 0000 | 0010 => 0010
	if chiffre {

		ext |= 1 << ExtensionChiffrement
	}
	return ext
}

// -----------------------------------------------------------------------------------------------------
// ParseExtensions extrait le champ "Extensions" d'un message Hello/HelloReply.
// Le champ Extensions est codé sur 4 octets au début du body du message, en big-endian.
// body : le tableau d'octets représentant le body du message
// Retour :
//   - uint32 : la valeur du champ Extensions reconstituée
//   - error  : renvoyé si le body est trop court pour contenir le champ
func ParseExtensions(body []byte) (uint32, error) {

	// Vérifie que le body contient au moins 4 octets pour le champ Extensions
	if len(body) < 4 {
		if debugExtension {
			fmt.Println("Erreur aucun champ Extension Trouvé !")
		}
		return 0, fmt.Errorf("Erreur aucun champ Extension Trouvé !") // retourne une erreur si le body est trop court
	}

	// Reconstruit la valeur uint32 à partir des 4 octets du body
	// Big-endian :
	//   body[0] -> bits 31 à 24 (octet le plus significatif)
	//   body[1] -> bits 23 à 16
	//   body[2] -> bits 15 à 8
	//   body[3] -> bits 7 à 0 (octet le moins significatif)
	ext := uint32(body[0])<<24 |
		uint32(body[1])<<16 |
		uint32(body[2])<<8 |
		uint32(body[3])

	// Retourne la valeur reconstruite et nil pour l'erreur
	return ext, nil
}

// -----------------------------------------------------------------------------------------------------
// Vérifier si le peer implémente l'extension de diffie Helmann et chiffre ses messages
func IsChiffrementEnabled(body []byte) bool {
	ext, err := ParseExtensions(body)
	if err != nil {
		return false
	}
	// On fait un et logique car 1 & 0 => 0 et 1 & 1 => 1 donc si le bit extensionChiffrement vaut 1
	// alors on aura valeur 2 (c'est plus sûr de faire != 0 : si on change le bit de extension chiffrement, par exemple)
	// si le bit ne vaut pas 1 alors tout le reste est à 0 et ce bit aussi donc la valeur finale est 0 : c'est un masque qui agit comme filtre
	return (ext & (1 << ExtensionChiffrement)) != 0
}
