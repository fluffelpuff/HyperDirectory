package crypto

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
)

func RandomBase32Secret() string {
	randomBytes := make([]byte, 92)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return base32.StdEncoding.EncodeToString(randomBytes)[:64]
}

func RandomHex64Secret() string {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	hexed := hex.EncodeToString(randomBytes)
	return hexed
}

func RandomHex32Secret() string {
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	hexed := hex.EncodeToString(randomBytes)
	return hexed
}
