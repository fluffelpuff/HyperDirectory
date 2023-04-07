package database

import (
	"database/sql"
	"fmt"
	"hyperdirectory/base"
	"time"

	hdsha3 "hyperdirectory/crypto/sha3"
)

/*
Wird verwendet um einen Request in die Datenbank zu schreiben
*/
func (obj *Database) OpenNewRequestEntryAndGetId(request_data *base.RequestMetaData, function_name string, proxy_pass bool) (*base.RequestMetaDataDbEntry, error) {
	// Der Threadlock wird ausgeführt
	obj.lock.Lock()

	// Die Aktuelle sowie die Ablaufzeit wird ermittelt
	current_time := time.Now()

	// Es wird ein Eintrag für diesen Request erstellt
	request_add_result, err := obj.db.Exec(SQLITE_WRITE_REQUEST_START, request_data.UserAgent, request_data.Domain, request_data.Accept, request_data.Encodings, request_data.Connection, request_data.ContentLength, request_data.ContentType, request_data.SourceIp, request_data.SourcePort, function_name, current_time.Unix())
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("OpenNewRequestEntryAndGetId: " + err.Error())
	}

	// Die ID des neuen Eintrages wird ermittelt
	add_req_id, err := request_add_result.LastInsertId()
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("OpenNewRequestEntryAndGetId: " + err.Error())
	}

	// Das Rückgabeobjekt wird erstellt
	resturn := base.RequestMetaDataDbEntry{DbEntryId: add_req_id}

	// Der ThreadLock wird freigegeben
	obj.lock.Unlock()

	// Die DirectoryServiceProcess Daten werden zurückgegben
	return &resturn, nil
}

/*
Wird verwendet um einen Dienste API-Benutzer zu Authentifizieren
*/
func (obj *Database) ValidateDirectoryAPIUserAndGetProcessId(verify_cert_fingerprint_unp string, user_agent string, host string, accept string, encodings string, connection string, clen string, content_type string, source_ip string, source_port string, function_name string, source_meta_data base.RequestMetaDataDbEntry) (bool, *base.DirectoryServiceProcess, error) {
	// Es wird geprüft ob der Token 64 Zeichen lang ist
	is_validate_finger_print, pre_finger_print := validateCertFingerprintDBEntry(verify_cert_fingerprint_unp)
	if !is_validate_finger_print {
		return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: invalid fingerprint")
	}

	// Der Threadlock wird ausgeführt
	obj.lock.Lock()

	// Es wird geprüft ob der API Benutzer exestiert
	var dsauid int64
	if err := obj.db.QueryRow(SQLITE_CHECK_SERVICE_API_USER_CREDENTIALS, base.PrepareText(pre_finger_print)).Scan(&dsauid); err != nil {
		obj.lock.Unlock()
		if err.Error() != "sql: no rows in result set" {
			return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: " + err.Error())
		}
		return false, nil, nil
	}
	if dsauid == 0 {
		obj.lock.Unlock()
		return false, nil, nil
	}

	// Die Aktuelle sowie die Ablaufzeit wird ermittelt
	current_time := time.Now()

	// Es wird ein Eintrag für diesen Request erstellt
	request_add_result, err := obj.db.Exec(SQLITE_WRITE_NEW_SESSION_DATA, dsauid, user_agent, host, accept, encodings, connection, clen, content_type, source_ip, source_port, function_name, current_time.Unix(), source_meta_data.DbEntryId)
	if err != nil {
		obj.lock.Unlock()
		return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: " + err.Error())
	}

	// Die ID des neuen Eintrages wird ermittelt
	add_req_id, err := request_add_result.LastInsertId()
	if err != nil {
		obj.lock.Unlock()
		return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: " + err.Error())
	}

	// Das Rückgabeobjekt wird erstellt
	resturn := base.DirectoryServiceProcess{DatabaseId: add_req_id, StartingTime: current_time}

	// Es werden alle berechtigungen für diesen Benutzer abgerufen
	rows, err := obj.db.Query(SQLITE_GET_ALL_SERVICES_API_USER_REMISSIONS, dsauid)
	if err != nil {
		obj.lock.Unlock()
		return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: " + err.Error())
	}

	// Lesen Sie die Ergebnisse der Abfrage
	for rows.Next() {
		// Es wird versucht den Aktuellen Wert auszulesen
		var value string
		err = rows.Scan(&value)
		if err != nil {
			obj.lock.Unlock()
			return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: " + err.Error())
		}

		// Der Wert wird zwischengespeichert
		resturn.AllowedFunctions = append(resturn.AllowedFunctions, value)
	}

	// Die Anfrage wird aus Sicherheitsgründen wieder geschlossen
	if err := rows.Close(); err != nil {
		obj.lock.Unlock()
		return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: " + err.Error())
	}

	// Der ThreadLock wird freigegeben
	obj.lock.Unlock()

	// Die DirectoryServiceProcess Daten werden zurückgegben
	return true, &resturn, nil
}

/*
Wird verwendet um zu überprüfen ob die Benutzerdaten noch verfügbar sind
*/
func _checkUserDataAvailability(db *sql.DB, prep_email string, prep_master_pkey string, pre_owner_pkey string) (bool, bool, bool, error) {
	// Es wird geprüft ob die E-Mail Adresse derzeit Aktiv verwendet wird
	var total_active_mails int64
	if err := db.QueryRow(SQLITE_CHECK_EMAIL_IN_DB, base.PrepareText(prep_email)).Scan(&total_active_mails); err != nil {
		if err.Error() != "sql: no rows in result set" {
			return false, false, false, fmt.Errorf("_checkUserDataAvailability: " + err.Error())
		}
		return false, false, false, nil
	}

	// Es wird geprüft ob der Master Schlüssel derzeit Aktiv verwendet wird
	var total_active_pk_mater_keys int64
	if err := db.QueryRow(SQLITE_CHECK_PKEY_IKNOWN, base.PrepareText(prep_master_pkey)).Scan(&total_active_pk_mater_keys); err != nil {
		if err.Error() != "sql: no rows in result set" {
			return false, false, false, fmt.Errorf("_checkUserDataAvailability: " + err.Error())
		}
		return false, false, false, nil
	}

	// Es wird geprüft ob der Owner Schlüssel derzeit Aktiv verwendet wird
	var total_active_owner_pk_keys int64
	if err := db.QueryRow(SQLITE_CHECK_PKEY_IKNOWN, base.PrepareText(pre_owner_pkey)).Scan(&total_active_pk_mater_keys); err != nil {
		if err.Error() != "sql: no rows in result set" {
			return false, false, false, fmt.Errorf("_checkUserDataAvailability: " + err.Error())
		}
		return false, false, false, nil
	}

	// Es wird geprüft ob der Master Schlüssel derzeit Aktiv als Master verwendet wird
	var total_active_pk_master_master_keys int64
	if err := db.QueryRow(SQLITE_CHECK_USER_WITH_MASTER_PKEY_EXIST, base.PrepareText(prep_master_pkey)).Scan(&total_active_pk_master_master_keys); err != nil {
		if err.Error() != "sql: no rows in result set" {
			return false, false, false, fmt.Errorf("_checkUserDataAvailability: " + err.Error())
		}
		return false, false, false, nil
	}

	// Es wird geprüft ob der Owner Schlüssel derzeit Aktiv als Master verwendet wird
	var total_active_pk_owner_master_keys int64
	if err := db.QueryRow(SQLITE_CHECK_USER_WITH_MASTER_PKEY_EXIST, base.PrepareText(pre_owner_pkey)).Scan(&total_active_pk_owner_master_keys); err != nil {
		if err.Error() != "sql: no rows in result set" {
			return false, false, false, fmt.Errorf("_checkUserDataAvailability: " + err.Error())
		}
		return false, false, false, nil
	}

	// Die Daten werden zurückgegeben
	return total_active_mails == 0, total_active_pk_mater_keys == 0 && total_active_pk_master_master_keys == 0, total_active_owner_pk_keys == 0 && total_active_pk_owner_master_keys == 0, nil
}

func (obj *Database) CheckUserDataAvailability(email string, pkey_master string, pkey_owner string, service_data *base.DirectoryServiceProcess, source_meta_data base.RequestMetaDataDbEntry, is_primary_fnc bool) (bool, bool, bool, error) {
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
Ruft alle Verfügbaren Gruppen für einen Benutzer abgerufen
*/
func (obj *Database) GetAllMetaUserGroupsByDirectoryApiUser(filter_mode base.GetDataMode, service_data *base.DirectoryServiceProcess, filters []base.PremissionFilter, group_names ...string) ([]string, error) {
	// Es wird geprüft ob das Datenbank Objekt verfügbar ist
	if obj.db == nil {
		return nil, fmt.Errorf("GetAllUserGroupsByDirectoryApiUser: internal db error")
	}

	// Es wird geprüft ob ein Benutezr übergeben wurde
	if service_data == nil {
		return nil, fmt.Errorf("GetAllUserGroupsByDirectoryApiUser: No user available")
	}

	// Der Threadlock wird verwendet
	obj.lock.Lock()

	// Es werden alle berechtigungen für diesen Benutzer abgerufen
	var service_id *int64
	var user_authed_active *string
	err := obj.db.QueryRow(SQLITE_GET_ALL_SERVICES_API_USER_REMISSIONS, service_data.DatabaseId).Scan(user_authed_active, service_id)
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("GetAllUserGroupsByDirectoryApiUser: " + err.Error())
	}

	// Sollte der Benutzer nicht berechtigt sein wird der Vorgang hier abgebrochen
	if user_authed_active == nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("GetAllUserGroupsByDirectoryApiUser: internal error")
	}
	if *user_authed_active != "YES" {
		obj.lock.Unlock()
		return nil, fmt.Errorf("GetAllUserGroupsByDirectoryApiUser: the service could not be authenticated")
	}

	// Es wird geprüft ob die Service ID abgerufen wurde
	if service_id == nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("GetAllUserGroupsByDirectoryApiUser: internal error")
	}
	if *service_id < -10 {
		obj.lock.Unlock()
		return nil, fmt.Errorf("GetAllUserGroupsByDirectoryApiUser: internal error")
	}

	obj.lock.Unlock()

	// Die
	return []string{}, nil
}

/*
Wird verwendet um einen neuen Benutzer zu registrieren
*/
func (obj *Database) CreateNewUserNoneRoot(cred_owner_pkey string, enc_master_key string, master_pkey string, email_address string, encrypted_password string, gender string, first_name []string, last_name []string, service_data *base.DirectoryServiceProcess, source_meta_data base.RequestMetaDataDbEntry) (*base.NewUserDbResult, error) {
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

	// Die Aktuelle ServiceID wird ermittelt
	c_service_id := 0
	if service_data != nil {
		c_service_id = int(service_data.DatabaseId)
	}

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
	root_result, err := obj.db.Exec(SQLITE_CREATE_NEW_NONE_ROOT_USER, current_time.Unix(), 1, prep_master_pkey, gender, -2, source_meta_data.DbEntryId, c_service_id)
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
	email_writing_result, err := obj.db.Exec(SQLITE_WRITE_EMAIL_ADDRESS, user_id, prep_email, e_match_hash, 1, current_time.Unix(), c_service_id, source_meta_data.DbEntryId, -2)
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
	_, err = obj.db.Exec(SQLITE_WRITE_LOGIN_CREDENTIALS, user_id, 1, email_id, current_time.Unix(), cred_owner_pkey, encrypted_password, enc_master_key, c_service_id, source_meta_data.DbEntryId, -2)
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
	}

	// Die Verfügbaren Vornamen werden in die Datenbank geschrieben
	for i := range first_name {
		_, err := obj.db.Exec(SQLITE_WRITE_FIRSTNAME, first_name[i], current_time.Unix(), i, user_id, 1, c_service_id, source_meta_data.DbEntryId, -2)
		if err != nil {
			obj.lock.Unlock()
			return nil, fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
		}
	}

	// Die Verfügbaren Nachnamen werden in die Datenbank geschrieben
	for i := range last_name {
		_, err := obj.db.Exec(SQLITE_WRITE_LASTNAME, last_name[i], current_time.Unix(), 1, user_id, i, c_service_id, source_meta_data.DbEntryId, -2)
		if err != nil {
			obj.lock.Unlock()
			return nil, fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
		}
	}

	// Der Threadlock wird freigegeben
	obj.lock.Unlock()

	// Die Daten werden zusammengefasst und zurückgegeben
	return_value := base.NewUserDbResult{UserId: user_id, IsRoot: false}
	return &return_value, nil
}

/*
Gibt an ob die Login Credentials korrekt sind
*/
func (obj *Database) VerifyLoginCredentials(public_login_cred_key string, req_metadata *base.RequestMetaData) bool {
	// Der Lockguard wird gelockt
	obj.lock.Lock()

	// Es wird geprüft ob die Datenbank vorhanden ist

	// Es wird geprüft ob die SQLite Datenbank vorhanden ist
	return true
}

/*
Wird verwendet um den Aktuellen Login Process Hash abzurufen
*/
func (obj *Database) GetUserLoginProcessKey(public_login_cred_key string, req_metadata *base.RequestMetaData) (string, error) {
	return "nil", nil
}

/*
Wird verwendet um eine neue Sitzung zu erstellen
*/
func (obj *Database) CreateNewUserSession(public_login_cred_key string, public_login_cred_sig string, login_process_pkey string, req_metadata *base.RequestMetaData) (*base.UserSession, error) {
	return &base.UserSession{SessionId: "", LoginProcessHash: "", SessionBrowserPublicKey: "", SessionServerPublicKey: "", SessionServerSignature: ""}, nil
}

/*
Wird verwendet um die Metadaten einer Sitzung abzurufen
*/
func (obj *Database) GetSessionFromDbById(session_id string, req_metadata *base.RequestMetaData) (*base.UserSession, error, error) {
	return nil, nil, nil
}

/*
Wird verwendet um die Login Credentials abzurufen
*/
func (obj *Database) GetLoginCredentialsBySessionId(session_id string, req_metadata *base.RequestMetaData, primary_only bool) ([]*base.LoginCredentials, error, error) {
	return nil, nil, nil
}

/*
Wird verwendet um die API Credentials abzurufen
*/
func (obj *Database) GetApiCredentialsBySessionId(session_id string, req_metadata *base.RequestMetaData) ([]*base.ApiCredentials, error, error) {
	return nil, nil, nil
}

/*
Wird verwendet um alle Apps eines Benutzers abzurufen
*/
func (obj *Database) GetAppCredentialsBySessionId(session_id string, req_metadata *base.RequestMetaData) ([]*base.AppCredentials, error, error) {
	return nil, nil, nil
}

// Wird verwendet um die Schlüsselpaare eines Benutzers abzurufen
func (obj *Database) GetKeyPairsBySessionId(session_id string, req_metadata *base.RequestMetaData, primary_only bool) ([]*base.UserKeyPair, error, error) {
	return nil, nil, nil
}

// Wird verwendet um die Gruppen in denen der Benutzer ist anzuzeigen
func (obj *Database) GetUserGroupsBySessionId(session_id string, req_metadata *base.RequestMetaData) ([]*base.UserGroupData, error, error) {
	return nil, nil, nil
}
