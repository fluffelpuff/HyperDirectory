package sha3

import (
	"fmt"

	"golang.org/x/crypto/sha3"
)

func ComputeSha256(v string) string {
	h := sha3.New512()
	h.Write([]byte(v))
	return fmt.Sprintf("%x", h.Sum(nil))
}
