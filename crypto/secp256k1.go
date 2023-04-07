package crypto

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
)

func IsSecp256k1PublicKey(pubKey string) bool {
	// Es wird geprüft ob die Länge des Hexstrings korrekt ist
	if len(pubKey) != 66 {
		return false
	}

	// Es wird versucht den String zu Dekodieren
	data, err := hex.DecodeString(pubKey)
	if err != nil {
		return false
	}

	// Es wird geprüft ob die Länge
	if len(data) != 33 {
		return false
	}

	// Parse the public key as a btcec public key
	_, err = btcec.ParsePubKey(data)
	return err == nil
}

func ECIESSecp256k1PublicKeyEncryptString(pubkey string, data string) (string, error) {
	return "", nil
}
