package base

import (
	hcrypto "github.com/fluffelpuff/HyperDirectory/crypto"
)

type CreateNewUserNoneRoot struct {
	CredentialsOwnerSignature *string
	CredentialsOwnerPublicKey *string
	EncryptedUserPassword     *string
	CreateClientSession       *bool
	MasterKeySignature        *string
	EncryptedMasterKey        *string
	PublicMasterKey           *string
	EMailAddress              *string
	FirstName                 []string
	LastName                  []string
	Gender                    *string
	MetaData                  *RequestMetaData
}

func (t *CreateNewUserNoneRoot) PreValidate() bool {
	// Es wird geprüft ob das Objekt korrekt ist
	if t == nil {
		return false
	}
	if t.CredentialsOwnerSignature == nil {
		return false
	}
	if t.CredentialsOwnerPublicKey == nil {
		return false
	}
	if t.EncryptedUserPassword == nil {
		return false
	}
	if t.MasterKeySignature == nil {
		return false
	}
	if t.CreateClientSession == nil {
		return false
	}
	if t.EncryptedMasterKey == nil {
		return false
	}
	if t.PublicMasterKey == nil {
		return false
	}
	if t.EMailAddress == nil {
		return false
	}
	if t.Gender == nil {
		return false
	}

	// Es wird geprüft ob der Vorname korrekt ist, sollte er vorhanden sein
	if len(t.FirstName) > 0 {
		for i := range t.FirstName {
			if !IsValidateHumanName(t.FirstName[i]) {
				return false
			}
		}
	}

	// Es wird geprüft ob der Nachname korrekt ist, sollte er vorhanden sein
	if len(t.LastName) > 0 {
		for i := range t.LastName {
			if !IsValidateHumanName(t.LastName[i]) {
				return false
			}
		}
	}

	// Es wird geprüft ob es sich um ein zulässiges Geschlecht handelt
	if !ValidateGender(*t.Gender) {
		return false
	}

	// Es wird geprüft ob es sich um eine zulässige E-Mail Adresse handelt
	if !ValidateEMail(*t.EMailAddress) {
		return false
	}

	// Es wird geprüft ob es sich um einen zulässigen Öffentlichen Master Schlüssel handelt
	if !hcrypto.IsSecp256k1PublicKey(*t.PublicMasterKey) {
		return false
	}

	// Es wird geprüft ob es sich um einen zulässigen Öffentlichen Master Schlüssel handelt
	if !hcrypto.IsSecp256k1PublicKey(*t.CredentialsOwnerPublicKey) {
		return false
	}

	// Der Vorgang wurde erfolgreich durchgeführt
	return true
}
