package client

import (
	"encoding/binary"
	"fmt"
	"net"
)

var debugParse = false

/*
0..3   : Id        (4 bytes)
4      : Type      (1 byte)
5..6   : Length    (2 bytes)
7..    : Body
...    : Signature (optionnelle, 64 bytes)
*/
const (
	// Offsets (positions dans le paquet)
	OffsetID       = 0
	OffsetType     = 4
	OffsetLength   = 5
	EndLength      = 6
	OffsetBody     = 7
	ExtensionField = 4

	// Tailles
	SizeID        = 4
	SizeType      = 1
	SizeLength    = 2
	SizeSignature = 64

	// Taille minimale sans body ni signature
	HeaderSize = OffsetBody
)

// ------------------------------------------------------------------------------------
// getID renvoie l'ID d'un paquet
func getID(pkt []byte) (uint32, bool) {
	if len(pkt) < HeaderSize {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[OffsetID : OffsetID+SizeID]), true
}

// ------------------------------------------------------------------------------------
// getType renvoie le type d'un paquet
func getType(pkt []byte) (uint8, bool) {
	if len(pkt) < OffsetLength {
		return 0, false
	}
	return pkt[OffsetType], true
}

// ------------------------------------------------------------------------------------
// getBody renvoie le corps du message et sa longueur
func getBody(pkt []byte) ([]byte, int, bool) {
	if len(pkt) < HeaderSize {
		return nil, 0, false
	}
	bodyLen := int(pkt[OffsetLength])<<8 | int(pkt[EndLength])
	if len(pkt) < HeaderSize+bodyLen {
		if debugParse {
			fmt.Println("Paquet body déclaré plus long que reçu, ignoré")
		}
		return nil, 0, false
	}
	body := pkt[OffsetBody : OffsetBody+bodyLen]
	return body, bodyLen, true
}

// ------------------------------------------------------------------------------------
// getSigned renvoie le segment signé (jusqu'à la fin du body)
func getSigned(pkt []byte) ([]byte, bool) {
	if len(pkt) < HeaderSize {
		return nil, false
	}
	bodyLen := int(pkt[OffsetLength])<<8 | int(pkt[EndLength])
	if len(pkt) < HeaderSize+bodyLen {
		return nil, false
	}
	signed := pkt[:OffsetBody+bodyLen]

	return signed, true
}

// ------------------------------------------------------------------------------------
// getSig renvoie la signature si elle existe
func getSig(pkt []byte) ([]byte, bool) {
	bodyLen := int(pkt[OffsetLength])<<8 | int(pkt[EndLength])
	if len(pkt) < HeaderSize+bodyLen+SizeSignature {
		return nil, false
	}
	sig := pkt[OffsetBody+bodyLen : OffsetBody+bodyLen+SizeSignature]
	return sig, true
}

// ------------------------------------------------------------------------------------
// parseRecvMessage peut maintenant être simplifiée en appelant les utilitaires
func parseRecvMessage(pkt []byte) (uint32, uint8, int, []byte, []byte, []byte, bool) {
	id, ok := getID(pkt)
	if !ok {
		return 0, 0, 0, nil, nil, nil, false
	}
	typ, ok := getType(pkt)
	if !ok {
		return 0, 0, 0, nil, nil, nil, false
	}
	body, bodyLen, ok := getBody(pkt)
	if !ok {
		return 0, 0, 0, nil, nil, nil, false
	}
	signed, ok1 := getSigned(pkt)
	sig, ok2 := getSig(pkt)

	if !ok1 || !ok2 {
		if debugParse {
			fmt.Println("le paquet est non signé !")
		}
		return id, typ, bodyLen, body, nil, nil, true
	}

	return id, typ, bodyLen, body, signed, sig, true
}

// ------------------------------------------------------------------------------------
// ParseNATBody parse le body d'un NatTraversalRequest ou NatTraversalRequest2
// et retourne une *net.UDPAddr correspondant à l'adresse cible.
func ParseNATBody(body []byte, len uint8) (*net.UDPAddr, error) {
	switch len {
	case 6: // IPv4
		ip := net.IP(body[:4])
		port := int(binary.BigEndian.Uint16(body[4:6]))
		return &net.UDPAddr{
			IP:   ip,
			Port: port,
		}, nil
	case 18: // IPv6
		ip := net.IP(body[:16])
		port := int(binary.BigEndian.Uint16(body[16:18]))
		return &net.UDPAddr{
			IP:   ip,
			Port: port,
		}, nil
	default:
		if debugParse {
			fmt.Println("unexpected NAT body length")
		}
		return nil, fmt.Errorf("unexpected NAT body length: %d", len)
	}
}
