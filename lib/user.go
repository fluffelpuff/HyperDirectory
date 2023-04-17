package main

import (
	"fmt"

	"github.com/fluffelpuff/HyperDirectory/base"
	hd "github.com/fluffelpuff/HyperDirectory/base"
	hdcrypto "github.com/fluffelpuff/HyperDirectory/crypto"
	hdsha "github.com/fluffelpuff/HyperDirectory/crypto/sha3"
)

// Wird verwndet um einen neuen Benutzer zu erstellen
func (obj *RpcClient) CreateNewUser(master_key_pair hdcrypto.MasterKeyPair, email_address string, password string, gender string, first_names []string, last_names []string) {
	// Es wird geprüft ob es sich um ein zulässiges Geschlecht handelt
	if !hd.ValidateGender(gender) {

	}

	// Es wird geprüft ob es sich um eine zulässige E-Mail Adresse handelt
	if !hd.ValidateEMail(email_address) {

	}

	// Es wird geprüft ob der Vorname korrekt ist, sollte er vorhanden sein
	for i := range first_names {
		if !base.IsValidateHumanName(first_names[i]) {

		}
	}

	// Es wird geprüft ob der Nachname korrekt ist, sollte er vorhanden sein
	for i := range last_names {
		if !base.IsValidateHumanName(last_names[i]) {

		}
	}

	// Aus der E-Mail Adresse und dem Password wird der sogenanten Login Credentails Key erzeugt
	login_cred_keypair, err := hdcrypto.CreateLoginCredentialsKeyPairFromEMailAndPassword(email_address, password)
	if err != nil {

	}

	// Der Private Masterschlüssel wird mit den Öffentlichen Login Credentials Schlüssel verschlüsselt
	encrypted_master_key, err := login_cred_keypair.ECIESSecp256k1PublicKeyEncryptString(master_key_pair.PrivateKey)
	if err != nil {

	}

	// Das Passwort des Benutzers wird mit dem MasterKey verschlüsselt
	encrypted_user_passwird, err := master_key_pair.ECIESSecp256k1PublicKeyEncryptString(password)
	if err != nil {

	}

	// Das Verschlüsselte Password wird nun nocheinmal mit dem Öffentlichen Schlüssel des Login Schlüssels verschlüsselt
	double_encrypted_user_passwird, err := login_cred_keypair.ECIESSecp256k1PublicKeyEncryptString(encrypted_user_passwird)
	if err != nil {

	}

	// Der Signaturhash wird erzeugt
	sha3_hash := hdsha.ComputeSha256(email_address + password + gender + encrypted_master_key + double_encrypted_user_passwird + master_key_pair.PublicKey + login_cred_keypair.PublicKey)

	// Der Signaturhash wird mit dem Master und mit dem Login Credentials Key signiert
	master_key_signature, err := master_key_pair.SignString(sha3_hash)
	if err != nil {

	}

	// Der Signaturhash wird mit dem Login Credentials Key signiert
	credentials_key_signature, err := login_cred_keypair.SignString(sha3_hash)
	if err != nil {

	}

	// Der Finale Request wird erstellt
	fmt.Println(master_key_signature, credentials_key_signature)
}

// Wird verwendet um einen neue Benutzer Sitzung zu erstellen
func (obj *RpcClient) CreateNewLoginProcessForUser(email_address string, password string) {

}

// Weißt einem Benutzer einer Gruppe zu
func (obj *RpcClient) SetUserToMemberOfGroup(user_service_id string, group_names string) {

}

// Ruft alle Benutzergruppen ab
func (obj *RpcClient) GetAllGroupsOfUserByUSID(user_service_id string, group_names string) {

}

// Löscht einen Benutzer aus einer Gruppe
func (obj *RpcClient) DeleteUserFromGroupByUSID(user_service_id string, group_names string) {

}
