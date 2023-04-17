package database

import (
	"fmt"
	"time"

	"github.com/fluffelpuff/HyperDirectory/base"
	hdcrypto "github.com/fluffelpuff/HyperDirectory/crypto"
	hdsha3 "github.com/fluffelpuff/HyperDirectory/crypto/sha3"
)

/*
Wird verwendet um eine neue Session anhand der Nutzerdaten zu erstellen
*/
func (obj *Database) CreateNewUserSessionByUID(userid int64, service_data *base.DirectoryServiceProcess, session_req base.RequestMetaDataSession) (*base.UserSessionDbResult, error) {
	// Es wird geprüft ob das Datenbank Objekt verfügbar ist
	if obj.db == nil {
		return nil, fmt.Errorf("CreateNewUserSessionByUID: internal db error")
	}

	// Es wird geprüft ob die Quell Metadaten verfügabr sind, wenn nein wird der Vorgang abgebrochen
	if service_data == nil {
		return nil, fmt.Errorf("CreateNewUserSessionByUID: request has no meta data, aborted")
	}

	// Es wird geprüft ob es sich um eine Zulässige UserID handelt
	if userid <= 0 {
		return nil, fmt.Errorf("CreateNewUserSessionByUID: cant create session for unkown user")
	}

	// Die Aktuelle sowie die Ablaufzeit wird ermittelt
	current_time := time.Now()

	// Es wird ein Schlüsselpaar erzeugt, dieses Schlüsselpaar wird an den Client übertragen
	client_session_key_pair, err := hdcrypto.CreateRandomKeypair()
	if err != nil {
		return nil, fmt.Errorf("CreateNewUserSessionByUID: " + err.Error())
	}

	// Es wird ein weiteres Schlüsselpaar erstellt, dieses Schlüsselpaar wird nicht an den Client übertragen, nur der Öffentliche Schlüssel wird übertragen
	server_session_key_pair, err := hdcrypto.CreateRandomKeypair()
	if err != nil {
		return nil, fmt.Errorf("CreateNewUserSessionByUID: " + err.Error())
	}

	// Es wird ein 64Bit Fingerprint aus der SessionId erstellt
	fingerprint := hdsha3.ComputeSha64Int64(server_session_key_pair.PublicKey)

	// Der Threadlock wird ausgeführt
	obj.lock.Lock()

	// Es wird geprüft ob Benutzer teil des Dienstes ist sowie Aktiv
	var allowed_pass string
	if err := obj.db.QueryRow(SQLITE_CHECK_USER_SERVICES_STATE_AND_MEMBERSHIP, userid, service_data.DbServiceId).Scan(&allowed_pass); err != nil {
		obj.lock.Unlock()
		return nil, err
	}
	if allowed_pass != "YES" {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewUserSessionByUID: ")
	}

	// Es wird eine neue Sitzung für den Aktuellen Benutzer erstellt
	root_result, err := obj.db.Exec(SQLITE_WRITE_CREATE_USER_SESSION, userid, service_data.DbServiceId, -2, current_time.Unix(), client_session_key_pair.PublicKey, server_session_key_pair.PrivateKey, fingerprint, -1, service_data.DbServiceUserId, session_req.DbEntryId, -2)
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewUserSessionByUID: " + err.Error())
	}

	// Die ID des neuen Eintrages wird ermittelt
	session_db_id, err := root_result.LastInsertId()
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewUserSessionByUID: " + err.Error())
	}

	// Der Threadlock wird freiegeben
	obj.lock.Unlock()

	// Das Sitzungsobjekt wird erstellt
	return_value := new(base.UserSessionDbResult)
	return_value.SessionDbId = session_db_id
	return_value.ClientsidePrivKey = client_session_key_pair.PrivateKey
	return_value.ClintsidePkey = server_session_key_pair.PublicKey

	// der Vorgang wurde erfolgreich durchgeführt
	return return_value, nil
}

/*
Wird verwendet um den Aktuellen Login Process Hash abzurufen
*/
func (obj *Database) CreateNewLoginProcessForUser(public_login_cred_key string, public_client_session_key string, service_data *base.DirectoryServiceProcess, session_req base.RequestMetaDataSession) (*base.LoginProcessKeyCreationDbResult, error) {
	// Es wird geprüft ob das Datenbank Objekt verfügbar ist
	if obj.db == nil {
		return nil, fmt.Errorf("CreateNewLoginProcessForUser: internal db error")
	}

	// Es wird Geprüft ob es sich um einen zulässigen Master Schlüssel handelt
	is_validate_master_pkey, prep_credt_pkey := validatePublicKeyDBEntry(public_login_cred_key)
	if !is_validate_master_pkey {
		return nil, fmt.Errorf("CreateNewLoginProcessForUser: invalid public master key")
	}

	// Es wird geprüft es sich um einen zulässigen Inhaber Schlüssel handelt
	is_validate_owner_pkey, pre_session_pkey := validatePublicKeyDBEntry(public_client_session_key)
	if !is_validate_owner_pkey {
		return nil, fmt.Errorf("CreateNewLoginProcessForUser: invalid public session key")
	}

	// Die Aktuelle sowie die Ablaufzeit wird ermittelt
	current_time := time.Now().Unix()

	// Es wird ein neues Schlüsselpaar erzeugt, dieses Schlüsselpaar wird verwendet um den LoginProzess abzuschlißen
	key_pair, err := hdcrypto.CreateRandomKeypair()
	if err != nil {
		return nil, fmt.Errorf("CreateNewLoginProcessForUser: " + err.Error())
	}

	// Der Threadlock wird verwendet
	obj.lock.Lock()

	// Es wird geprüft ob es einen Benutzer mit dem Entsprechenden Öffentlichen Credtials Key gibt
	var has_found string
	user_db_id := int64(-1)
	if err := obj.db.QueryRow(SQLITE_GET_LOGIN_CREDENTIALS_ACCEPTED_BY_PUB_KEY, prep_credt_pkey, service_data.DbServiceId).Scan(&has_found, &user_db_id); err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewLoginProcessForUser: " + err.Error())
	}
	if has_found != "FOUND" || user_db_id == -1 {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CloseEntrySessionRequest: ")
	}

	// Es wird geprüft ob der OneTimeKey bereits verwendet wird
	is_ok, err := _checkIsKeyInDb(obj, pre_session_pkey, uint64(service_data.DbServiceId))
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewLoginProcessForUser: " + err.Error())
	}

	// Sollte der Schlüssel bererits verwendet werden, wird der Vorgang abgebrochen
	if !is_ok {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewLoginProcessForUser: aborted, key double using not allowed")
	}

	// Es wird geprüft ob der Benutzer berechtigt ist sich anzumelden
	user_authed, user_granted, err := _validateUserCredentialsPKey(obj, prep_credt_pkey, service_data)
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewLoginProcessForUser: A" + err.Error())
	}

	// Sollte der Benutzer nicht berechtigt sein, wird der Vorgang abgebrochen
	if !user_authed || !user_granted {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewLoginProcessForUser: y: operation for user not granted")
	}

	// Es wird ein neuer Sitzungseintrag in der Datenbank erzeugt
	_, err = obj.db.Exec(SQLITE_WRITE_NEW_LOGIN_PROCESS, user_db_id, service_data.DbServiceId, pre_session_pkey, key_pair.PublicKey, key_pair.PrivateKey, current_time, service_data.DbServiceUserId, session_req.DbEntryId, -2)
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewLoginProcessForUser: " + err.Error())
	}

	// Der Threadlock wird freigegeben
	obj.lock.Unlock()

	// Das Rückgabe Objekt wird erzeugt
	result_obj := new(base.LoginProcessKeyCreationDbResult)
	result_obj.PublicLoginProcessKey = key_pair.PublicKey

	// Die Daten werden zurückgegeben
	return result_obj, nil
}

/*
Wird verwendet um zu überprüfen ob der Benutzer Vorhanden ist sowie Mitglied des Aktuellen Dienstes ist
*/
func _validateUserCredentialsPKey(db *Database, public_login_cred_key string, service_data *base.DirectoryServiceProcess) (bool, bool, error) {
	// Speicher die Filter Premssion ab welcher der Nutzer haben muss um sich anmelden zu können sofern diese Option Aktiviert ist
	filter_permission := "@signon"

	// Es wird geprüft ob es einen Benutzer mit dem Entsprechenden Öffentlichen Credtials Key gibt
	var has_found string
	if err := db.db.QueryRow(SQLITE_GET_ACTIVE_USER_DIRECTORY_SERVICE_BY_LOGIN_CREDENTIALS, public_login_cred_key, service_data.DbServiceId).Scan(&has_found); err != nil {
		return false, false, fmt.Errorf("ValidateUserCredentials: " + err.Error())
	}
	if has_found != "PERMITTED" {
		return false, false, nil
	}

	// Es wird geprüft ob es eine Spizielle berechtigung benötigt um sich anzumelden
	var has_filter string
	if err := db.db.QueryRow(SQLITE_GET_USER_GROUP_DIRECTORY_SERVICE_FILTER_SIGNON, service_data.DbServiceId, filter_permission).Scan(&has_filter); err != nil {
		return false, false, fmt.Errorf("ValidateUserCredentials: " + err.Error())
	}
	if has_filter == "YES" {
		// Es wird geprüft ob der Benutzer die Rechte direkt oder indirekt besitzt
		var has_perm_direct string
		var has_perm_trought_group string
		if err := db.db.QueryRow(SQLITE_GET_USER_HAS_PERMISSIONS_FOR_FILTER, public_login_cred_key, service_data.DbServiceId, filter_permission, filter_permission).Scan(&has_perm_direct, &has_perm_trought_group); err != nil {
			return false, false, fmt.Errorf("ValidateUserCredentials: " + err.Error())
		}

		// Sollte der Nutzer nicht berechtigt sein sich anzumelden wird der Vorgang abgebrochen
		if has_perm_direct != "GRANTED" && has_perm_trought_group != "GRANTED" {
			return true, false, nil
		}
	}

	// Der Vorgang wurde erfolgreich ausgeführt
	return true, true, nil
}

func (obj *Database) ValidateUserCredentialsPKey(public_login_cred_key string, service_data *base.DirectoryServiceProcess) (bool, bool, error) {
	// Es wird geprüft ob das Datenbank Objekt verfügbar ist
	if obj.db == nil {
		return false, false, fmt.Errorf("ValidateUserCredentials: internal db error")
	}

	// Es wird Geprüft ob es sich um einen zulässigen Master Schlüssel handelt
	is_validate_master_pkey, prep_credt_pkey := validatePublicKeyDBEntry(public_login_cred_key)
	if !is_validate_master_pkey {
		return false, false, fmt.Errorf("ValidateUserCredentials: invalid public master key")
	}

	// Der Threadlock wird verwendet
	obj.lock.Lock()

	// Es wird in einem Threadlock geprüft ob die Daten korrekt sind
	user_authed, user_granted, err := _validateUserCredentialsPKey(obj, prep_credt_pkey, service_data)
	if err != nil {
		obj.lock.Unlock()
		return false, false, fmt.Errorf("ValidateUserCredentialsPKey: " + err.Error())
	}

	// Der Threadlock wird freigegeben
	obj.lock.Unlock()

	// Der Vorgang wurde erfolgreich ausgeführt
	return user_authed, user_granted, nil
}

/*
Wird verwendet um zu ermitteln ob es eine Offene Wartende Sitzung für den Aktuellen Benutzer gibt
*/
func _hasOpenAndWaitingLoginProcessSessionForKey(obj *Database, public_login_session_key string, service_data *base.DirectoryServiceProcess) (string, string, bool, bool, error) {
	// Es wird geprüft ob es eine Offenne Sitzung für den Aktuellen Client gibt
	var pub_key string
	var priv_key string
	var found_start_proc string
	var found_session_for_process string
	if err := obj.db.QueryRow(SQLITE_GET_CHECK_AND_PRIV_KEY_BY_OPEN_LOGIN_PROCESSES, public_login_session_key, service_data.DbServiceId).Scan(&pub_key, &priv_key, &found_start_proc, &found_session_for_process); err != nil {
		return "", "", false, false, fmt.Errorf("ValidateUserCredentials: " + err.Error())
	}
	if found_start_proc != "YES" {
		return "", "", false, false, nil
	}
	if found_session_for_process != "YES" {
		return "", "", true, false, nil
	}

	// Die Daten werden zurückgegeben
	return pub_key, priv_key, true, true, nil
}

func (obj *Database) HasOpenAndWaitingLoginProcessSessionForKey(public_login_session_key string, service_data *base.DirectoryServiceProcess) (string, string, bool, bool, error) {
	// Es wird geprüft ob das Datenbank Objekt verfügbar ist
	if obj.db == nil {
		return "", "", false, false, fmt.Errorf("HasOpenAndWaitingLoginProcessSessionForKey: internal db error")
	}

	// Es wird Geprüft ob es sich um einen zulässigen Master Schlüssel handelt
	is_validate_master_pkey, prep_public_login_session_key := validatePublicKeyDBEntry(public_login_session_key)
	if !is_validate_master_pkey {
		return "", "", false, false, fmt.Errorf("HasOpenAndWaitingLoginProcessSessionForKey: invalid public session key")
	}

	// Der Threadlock wird verwendet
	obj.lock.Lock()

	// Prüft ob eine Wartende Sitzung gibt für diese Key
	public_client_key, private_decryption_key, session_foun, granted, err := _hasOpenAndWaitingLoginProcessSessionForKey(obj, prep_public_login_session_key, service_data)
	if err != nil {
		obj.lock.Unlock()
		return "", "", false, false, fmt.Errorf("HasOpenAndWaitingLoginProcessSessionForKey: " + err.Error())
	}

	// Der Threadlock wird freigegeben
	obj.lock.Unlock()

	// Die Daten werden zurückgegeben
	return public_client_key, private_decryption_key, session_foun, granted, nil
}
