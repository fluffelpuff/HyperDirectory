package base

import "github.com/fxamacker/cbor/v2"

type EncryptedLoginProcessStartCapsule struct {
	OneTimePublicKey string `cbor:"1,keyasint,omitempty"`
}

func (t *EncryptedLoginProcessStartCapsule) ToBytes() ([]byte, error) {
	encoded, err := cbor.Marshal(t)
	if err != nil {
		return nil, err
	}

	return encoded, nil
}
