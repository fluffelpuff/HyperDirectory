package database

import (
	"fmt"
	"time"

	"github.com/fluffelpuff/HyperDirectory/base"
	hdcrypto "github.com/fluffelpuff/HyperDirectory/crypto"
	hdsha3 "github.com/fluffelpuff/HyperDirectory/crypto/sha3"
)

/*
Wird verwendet um zu überprüfen ob die Benutzerdaten noch verfügbar sind
*/

func (obj *Database) CheckUserDataAvailability(email string, pkey_master string, pkey_owner string, service_data *base.DirectoryServiceProcess, session_req base.RequestMetaDataSession) (bool, bool, bool, error) {
	// Es wird geprüft ob das Datenbank Objekt verfügbar ist
	if obj.db == nil {
		return false, false, false, fmt.Errorf("CheckUserDataAvailability: internal db error")
	}

	// Es wird geprüft ob die E-Mail Adresse korrekt ist, wenn ja wird die E-Mail Adresse Vorbereitet zurückgegeben
	is_validate_email, prep_email := validateEMailDBEntry(email)
	if !is_validate_email {
		return false, false, false, fmt.Errorf("CheckUserDataAvailability: invalid email address")
	}

	// Es wird Geprüft ob es sich um einen zulässigen Master Schlüssel handelt
	is_validate_master_pkey, prep_master_pkey := validatePublicKeyDBEntry(pkey_master)
	if !is_validate_master_pkey {
		return false, false, false, fmt.Errorf("CheckUserDataAvailability: invalid public master key")
	}

	// Es wird geprüft es sich um einen zulässigen Inhaber Schlüssel handelt
	is_validate_owner_pkey, pre_owner_pkey := validatePublicKeyDBEntry(pkey_owner)
	if !is_validate_owner_pkey {
		return false, false, false, fmt.Errorf("CheckUserDataAvailability: invalid public onwer key")
	}

	// Es wird ein Hash aus der E-Mail Adresse erstellt
	e_match_hash := hdsha3.ComputeSha256(prep_email)

	// Der Threadlock wird verwendet
	obj.lock.Lock()

	// Es wird geprüft ob die Benutzerdaten verfügbar sind
	avail_email, avail_master_pkey, avail_owner_pkey, err := _checkUserDataAvailability(obj.db, e_match_hash, prep_master_pkey, pre_owner_pkey)

	// Der Threadlock wird freigegeben
	obj.lock.Unlock()

	// Sollte ein Fehler aufgetretn sein, wird dieser zurückgegeben
	if err != nil {
		return avail_email, avail_master_pkey, avail_owner_pkey, err
	}

	// Der Vorgang wurde erfolgreich durchgeführt
	return avail_email, avail_master_pkey, avail_owner_pkey, nil
}

/*
Wird verwendet um einen neuen Benutzer zu registrieren
*/
func (obj *Database) CreateNewUserNoneRoot(cred_owner_pkey string, enc_master_key string, master_pkey string, email_address string, encrypted_password string, gender string, first_name []string, last_name []string, service_data *base.DirectoryServiceProcess, session_req base.RequestMetaDataSession) (*base.NewUserDbResult, error) {
	// Es wird geprüft ob das Datenbank Objekt verfügbar ist
	if obj.db == nil {
		return nil, fmt.Errorf("CreateNewUserNoneRoot: internal db error")
	}

	// Es wird geprüft ob die E-Mail Adresse korrekt ist, wenn ja wird die E-Mail Adresse Vorbereitet zurückgegeben
	is_validate_email, prep_email := validateEMailDBEntry(email_address)
	if !is_validate_email {
		return nil, fmt.Errorf("CreateNewUserNoneRoot: invalid email address")
	}

	// Es wird Geprüft ob es sich um einen zulässigen Master Schlüssel handelt
	is_validate_master_pkey, prep_master_pkey := validatePublicKeyDBEntry(master_pkey)
	if !is_validate_master_pkey {
		return nil, fmt.Errorf("CreateNewUserNoneRoot: invalid public master key")
	}

	// Es wird geprüft es sich um einen zulässigen Inhaber Schlüssel handelt
	is_validate_owner_pkey, pre_owner_pkey := validatePublicKeyDBEntry(cred_owner_pkey)
	if !is_validate_owner_pkey {
		return nil, fmt.Errorf("CreateNewUserNoneRoot: invalid public onwer key")
	}

	// Es wird geprüft ob die Quell Metadaten verfügabr sind, wenn nein wird der Vorgang abgebrochen
	if service_data == nil {
		return nil, fmt.Errorf("CreateNewUserNoneRoot: request has no meta data, aborted")
	}

	// Die Aktuelle sowie die Ablaufzeit wird ermittelt
	current_time := time.Now()

	// Es wird ein Hash aus der E-Mail Adresse erstellt
	e_match_hash := hdsha3.ComputeSha256(prep_email)

	// Es wird eine RandomId erzeugt, diese Id ist nur dem Dienst zugänglich in dem sich dieser Benutzer gerade
	directory_user_id := hdcrypto.RandomHex32Secret()

	// Der Threadlock wird verwendet
	obj.lock.Lock()

	// Es wird geprüft ob die Benutzerdaten verfügbar sind
	avail_email, avail_master_pkey, avail_owner_pkey, err := _checkUserDataAvailability(obj.db, e_match_hash, prep_master_pkey, pre_owner_pkey)
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
	}
	if !avail_email || !avail_master_pkey || !avail_owner_pkey {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewUserNoneRoot: user data not avail")
	}

	// Es wird ein neuer Benutzer in der Datenbank angelegt
	root_result, err := obj.db.Exec(SQLITE_CREATE_NEW_NONE_ROOT_USER, current_time.Unix(), 1, prep_master_pkey, gender, -2, session_req.DbEntryId, service_data.DbServiceUserId)
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
	}

	// Die ID des neuen Eintrages wird ermittelt
	user_id, err := root_result.LastInsertId()
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
	}

	// Die Email Adresse wird hinzugefügt
	email_writing_result, err := obj.db.Exec(SQLITE_WRITE_EMAIL_ADDRESS, user_id, prep_email, e_match_hash, 1, current_time.Unix(), service_data.DbServiceUserId, session_req.DbEntryId, -2)
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
	}

	// Die ID des neuen Eintrages wird ermittelt
	email_id, err := email_writing_result.LastInsertId()
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
	}

	// Die Login Credentials werden hinzugefügt
	_, err = obj.db.Exec(SQLITE_WRITE_LOGIN_CREDENTIALS, user_id, 1, email_id, current_time.Unix(), cred_owner_pkey, encrypted_password, enc_master_key, service_data.DbServiceUserId, session_req.DbEntryId, -2)
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
	}

	// Der Benutzer wird dem Aktuellen Dienst zugeordnet
	_, err = obj.db.Exec(SQLITE_WRITE_SET_USER_MEMBERSHIP_OF_DIRECOTRY_SERVICE, user_id, service_data.DbServiceId, directory_user_id, 1, current_time.Unix(), service_data.DbServiceUserId, session_req.DbEntryId, -2)
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
	}

	// Die Verfügbaren Vornamen werden in die Datenbank geschrieben
	for i := range first_name {
		_, err := obj.db.Exec(SQLITE_WRITE_FIRSTNAME, first_name[i], current_time.Unix(), i, user_id, 1, service_data.DbServiceUserId, session_req.DbEntryId, -2)
		if err != nil {
			obj.lock.Unlock()
			return nil, fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
		}
	}

	// Die Verfügbaren Nachnamen werden in die Datenbank geschrieben
	for i := range last_name {
		_, err := obj.db.Exec(SQLITE_WRITE_LASTNAME, last_name[i], current_time.Unix(), 1, user_id, i, service_data.DbServiceUserId, session_req.DbEntryId, -2)
		if err != nil {
			obj.lock.Unlock()
			return nil, fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
		}
	}

	// Der Threadlock wird freigegeben
	obj.lock.Unlock()

	// Die Daten werden zusammengefasst und zurückgegeben
	return_value := base.NewUserDbResult{UserId: user_id, IsRoot: false, UserDirectoryId: directory_user_id}
	return &return_value, nil
}
