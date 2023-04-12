package base

import "github.com/fxamacker/cbor/v2"

type EncryptedSessionCapsule struct {
	ClientsidePrivKey string `cbor:"1,keyasint,omitempty"`
	ClintsidePkey     string `cbor:"2,keyasint,omitempty"`
}

func (t *EncryptedSessionCapsule) ToBytes() ([]byte, error) {
	encoded, err := cbor.Marshal(t)
	if err != nil {
		return nil, err
	}

	return encoded, nil
}
