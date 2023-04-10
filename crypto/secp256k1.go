package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	seck1ecies "github.com/ecies/go/v2"
)

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

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
	// Es wird geprüft ob es sich um einen Öffentlichen schlüssel handelt
	if !IsSecp256k1PublicKey(pubkey) {
		return "", fmt.Errorf("ECIESSecp256k1PublicKeyEncryptString: invalid public key")
	}

	// Es wird versucht den Öffentlichen Schlüssel zu dekodieren
	decoded_pkey, err := seck1ecies.NewPublicKeyFromHex(pubkey)
	if err != nil {
		return "", err
	}

	// Verschlüsselt die Nachricht
	ecrypted, err := seck1ecies.Encrypt(decoded_pkey, []byte(data))
	if err != nil {
		return "", fmt.Errorf("A:" + err.Error())
	}

	// Die Verschlüsselten Daten werden zurückgegeben
	hexed_ecrypted_data := hex.EncodeToString(ecrypted)
	return hexed_ecrypted_data, nil
}

func ECIESSecp256k1PublicKeyEncryptBytes(pubkey string, data []byte) (string, error) {
	// Es wird geprüft ob es sich um einen Öffentlichen schlüssel handelt
	if !IsSecp256k1PublicKey(pubkey) {
		return "", fmt.Errorf("ECIESSecp256k1PublicKeyEncryptString: invalid public key")
	}

	// Es wird versucht den Öffentlichen Schlüssel zu dekodieren
	decoded_pkey, err := seck1ecies.NewPublicKeyFromHex(pubkey)
	if err != nil {
		return "", err
	}

	// Verschlüsselt die Nachricht
	ecrypted, err := seck1ecies.Encrypt(decoded_pkey, data)
	if err != nil {
		return "", fmt.Errorf("A:" + err.Error())
	}

	// Die Verschlüsselten Daten werden zurückgegeben
	hexed_ecrypted_data := hex.EncodeToString(ecrypted)
	return hexed_ecrypted_data, nil
}

func CreateRandomKeypair() (*KeyPair, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	pubKey := privKey.PubKey()
	nwt := new(KeyPair)
	nwt.PrivateKey = hex.EncodeToString(privKey.Serialize())
	nwt.PublicKey = hex.EncodeToString(pubKey.SerializeCompressed())
	return nwt, nil
}
