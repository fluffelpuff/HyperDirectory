package sha3

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/sha3"
)

func ComputeSha256(v string) string {
	h := sha3.New512()
	h.Write([]byte(v))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func ComputeSha64Int64(v string) int64 {
	hash := sha3.Sum256([]byte(v))
	hash64 := binary.BigEndian.Uint64(hash[:8])
	return int64(hash64)
}
