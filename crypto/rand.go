package crypto

import (
	"crypto/rand"
	"encoding/base32"
)

func RandomBase32Secret() string {
	randomBytes := make([]byte, 92)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return base32.StdEncoding.EncodeToString(randomBytes)[:64]
}
