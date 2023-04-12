package database

import (
	"fmt"
	"strings"
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
Ruft alle Verfügbaren Gruppen für einen Benutzer abgerufen
*/
func (obj *Database) GetAllMetaUserGroupsByDirectoryApiUser(filter_mode base.GetDataMode, service_data *base.DirectoryServiceProcess, filters []base.PremissionFilter, group_names ...string) ([]*base.UserGroupDirectoryApiUser, error) {
	// Es wird geprüft ob das Datenbank Objekt verfügbar ist
	if obj.db == nil {
		return nil, fmt.Errorf("GetAllUserGroupsByDirectoryApiUser: internal db error")
	}

	// Es wird geprüft ob ein Benutezr übergeben wurde
	if service_data == nil {
		return nil, fmt.Errorf("GetAllUserGroupsByDirectoryApiUser: No user available")
	}

	// Die Verfügbaren und Aktiven Gruppenw welche diesem Service API User zugewiesen wurden, werden ermittelt
	var filter_set_group_member bool
	for i := range filters {
		switch filters[i] {
		case base.SET_GROUP_MEMBER:
			n_bool := true
			filter_set_group_member = n_bool
		default:
			obj.lock.Unlock()
			return nil, fmt.Errorf("GetAllUserGroupsByDirectoryApiUser: unsportted filter")
		}
	}

	// Es wwerden alle SET_GROUP berechtigten Gruppen abgerufen:
	//		- Der Dienst ist berechtigt diese Gruppe zu verwenden
	//		- Der Dienste API-User muss berechtigt sein Benutzer zu dieser Gruppe zuzuordnen
	extracted_group_from_datas := []*base.UserGroupDirectoryApiUser{}
	if filter_mode == base.FetchExplicit && filter_set_group_member {
		// Der Platzhalter befehlsstring wird erstellt
		placeholders := make([]string, len(group_names))
		for i := range group_names {
			placeholders[i] = "?"
		}

		// Die Verfügbaren Gruppen werden aufgearbeitet
		set_group_membership_interface := make([]interface{}, len(group_names))
		for i, v := range group_names {
			set_group_membership_interface[i] = v
		}

		// Der Threadlock wird verwendet
		obj.lock.Lock()

		// Der Befehl wird erstellt
		query_string := fmt.Sprintf(SQLITE_GET_SET_GROUP_PREMITTEDET_GROUPS_EXPLICIT, strings.Join(placeholders, ","))

		// Der Query wird vorbereitet
		total_query_parms := make([]interface{}, 0)
		total_query_parms = append(total_query_parms, 1)
		total_query_parms = append(total_query_parms, service_data.DbServiceUserId)
		total_query_parms = append(total_query_parms, set_group_membership_interface...)

		// Die Daten werden abgerufen
		rows, err := obj.db.Query(query_string, total_query_parms...)
		if err != nil {
			obj.lock.Unlock()
			return nil, fmt.Errorf("GetAllMetaUserGroupsByDirectoryApiUser: 1: " + err.Error())
		}

		// Die Abfrage wird ausgelesen
		for rows.Next() {
			// Die Antworten werden eingelesen
			new_item := new(base.UserGroupDirectoryApiUser)
			err = rows.Scan(&new_item.SetGroupMembershipPremission, &new_item.UserId, &new_item.DirectoryServiceId, &new_item.Name, &new_item.Id)
			if err != nil {
				obj.lock.Unlock()
				return nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: AA " + err.Error())
			}

			// Es wird geprüft ob die Service ID's übereinstimmen
			if new_item.UserId != service_data.DbServiceUserId {
				return nil, fmt.Errorf("GetAllMetaUserGroupsByDirectoryApiUser: Internal error")
			}
			if new_item.DirectoryServiceId != service_data.DbServiceId {
				return nil, fmt.Errorf("GetAllMetaUserGroupsByDirectoryApiUser: Internal error")
			}

			// Das Item wird zwischengespeichert
			extracted_group_from_datas = append(extracted_group_from_datas, new_item)
		}

		// Der Cursor wird geschlossen
		if err := rows.Close(); err != nil {
			obj.lock.Unlock()
			return nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: " + err.Error())
		}

		// Es wird geprüft ob alle benötigten Gruppen abgerufen wurden
		founds, not_founds := []string{}, []string{}
		for i := range group_names {
			has_found := false
			for x := range extracted_group_from_datas {
				if group_names[i] == extracted_group_from_datas[x].Name {
					has_found = true
					break
				}
			}
			if has_found {
				founds = append(founds, group_names[i])
			} else {
				not_founds = append(not_founds, group_names[i])
			}
		}

		// Es müssen genausoviele Gruppen gefunden wurden sein wie angefordert
		if len(founds) != len(group_names) {
			obj.lock.Unlock()
			return nil, fmt.Errorf(fmt.Sprintf("GetAllMetaUserGroupsByDirectoryApiUser: groups {%s} not found", strings.Join(not_founds, ",")))
		}

		// Der Threadlock wird freigegeben
		obj.lock.Unlock()
	}

	// Die Operation wurde erfolgreich ausgeführt, die Ergbnisse werden ohne Fehler zurückgegeben
	return extracted_group_from_datas, nil
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
	root_result, err := obj.db.Exec(SQLITE_WRITE_CREATE_USER_SESSION, userid, service_data.DbServiceId, -2, current_time.Unix(), client_session_key_pair.PublicKey, server_session_key_pair.PrivateKey, fingerprint, service_data.DbServiceUserId, session_req.DbEntryId, -2)
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
Wird verwendet um einen Offenen Session Request in der Datenbank zu schlißen
*/
func (obj *Database) CloseEntrySessionRequest(request_session *base.RequestMetaDataSession, warning *string, errort error) error {
	// Es wird geprüft ob das Datenbank Objekt verfügbar ist
	if obj.db == nil {
		return fmt.Errorf("CloseEntrySessionRequest: internal db error")
	}

	// Die Aktuelle sowie die Ablaufzeit wird ermittelt
	current_time := time.Now()

	// Der Threadlock wird verwendet
	obj.lock.Lock()

	// Es wird geprüft ob die Sitzung bereits geschlossen wurde, wenn ja wird der Vorgang abgebrochen
	var is_open string
	if err := obj.db.QueryRow(SQLITE_GET_META_REQUEST_CLOSED, request_session.DbEntryId).Scan(&is_open); err != nil {
		obj.lock.Unlock()
		return err
	}
	if is_open != "OPEN" {
		obj.lock.Unlock()
		return fmt.Errorf("CloseEntrySessionRequest: ")
	}

	// Die Request Session wird ohne fehler und oder warnung geschlossen
	if warning == nil && errort == nil {
		_, err := obj.db.Exec(SQLITE_WRITE_REQUEST_SESSION_CLOSE, request_session.DbEntryId, current_time.Unix())
		if err != nil {
			obj.lock.Unlock()
			return fmt.Errorf("CloseEntrySessionRequest: " + err.Error())
		}

		obj.lock.Unlock()
		return nil
	}

	// Es wird ermittelt ob eine Warnung oder einen Fehler gibt
	warning_str, errors_str := "", ""
	if warning != nil {
		warning_str = *warning
	}
	if errort != nil {
		errors_str = errort.Error()
	}

	// Die Daten werden in die Datenbank geschrieben
	_, err := obj.db.Exec(SQLITE_WRITE_REQUEST_SESSION_CLOSE_WITH_WARNING_OR_ERROR, request_session.DbEntryId, warning_str, errors_str, current_time.Unix())
	if err != nil {
		obj.lock.Unlock()
		return fmt.Errorf("CloseEntrySessionRequest: " + err.Error())
	}

	// Der Threadlock wird freigegeben
	obj.lock.Unlock()

	// Der Vorgang wurde erfolgreich durchgeführt
	return nil
}

/*
Wird verwendet um zu überprüfen ob der Benutzer Vorhanden ist sowie Mitglied des Aktuellen Dienstes ist
*/
func _validateUserCredentialsPKeyAndStartLoginProcess(db *Database, public_login_cred_key string, service_data *base.DirectoryServiceProcess) (bool, bool, error) {
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

func (obj *Database) ValidateUserCredentialsPKeyAndStartLoginProcess(public_login_cred_key string, service_data *base.DirectoryServiceProcess) (bool, bool, error) {
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
	user_authed, user_granted, err := _validateUserCredentialsPKeyAndStartLoginProcess(obj, prep_credt_pkey, service_data)
	if err != nil {
		obj.lock.Unlock()
		return false, false, fmt.Errorf("ValidateUserCredentialsPKeyAndStartLoginProcess: " + err.Error())
	}

	// Der Threadlock wird freigegeben
	obj.lock.Unlock()

	// Der Vorgang wurde erfolgreich ausgeführt
	return user_authed, user_granted, nil
}

/*
Wird verwendet um den Aktuellen Login Process Hash abzurufen
*/
func (obj *Database) CreateNewLoginProcessKey(public_login_cred_key string, public_client_session_key string, service_data *base.DirectoryServiceProcess, session_req base.RequestMetaDataSession) (*base.LoginProcessKeyCreationDbResult, error) {
	// Es wird geprüft ob das Datenbank Objekt verfügbar ist
	if obj.db == nil {
		return nil, fmt.Errorf("CreateNewLoginProcessKey: internal db error")
	}

	// Es wird Geprüft ob es sich um einen zulässigen Master Schlüssel handelt
	is_validate_master_pkey, prep_credt_pkey := validatePublicKeyDBEntry(public_login_cred_key)
	if !is_validate_master_pkey {
		return nil, fmt.Errorf("CreateNewLoginProcessKey: invalid public master key")
	}

	// Es wird geprüft es sich um einen zulässigen Inhaber Schlüssel handelt
	is_validate_owner_pkey, pre_session_pkey := validatePublicKeyDBEntry(public_client_session_key)
	if !is_validate_owner_pkey {
		return nil, fmt.Errorf("CreateNewLoginProcessKey: invalid public session key")
	}

	// Die Aktuelle sowie die Ablaufzeit wird ermittelt
	current_time := time.Now().Unix()

	// Es wird ein neues Schlüsselpaar erzeugt, dieses Schlüsselpaar wird verwendet um den LoginProzess abzuschlißen
	key_pair, err := hdcrypto.CreateRandomKeypair()
	if err != nil {
		return nil, fmt.Errorf("CreateNewLoginProcessKey: " + err.Error())
	}

	// Der Threadlock wird verwendet
	obj.lock.Lock()

	// Es wird geprüft ob es einen Benutzer mit dem Entsprechenden Öffentlichen Credtials Key gibt
	var has_found string
	user_db_id := int64(-1)
	if err := obj.db.QueryRow(SQLITE_GET_LOGIN_CREDENTIALS_ACCEPTED_BY_PUB_KEY, prep_credt_pkey, service_data.DbServiceId).Scan(&has_found, &user_db_id); err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewLoginProcessKey: " + err.Error())
	}
	if has_found != "FOUND" || user_db_id == -1 {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CloseEntrySessionRequest: ")
	}

	// Es wird geprüft ob der OneTimeKey bereits verwendet wird
	is_ok, err := _checkIsKeyInDb(obj, pre_session_pkey, uint64(service_data.DbServiceId))
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewLoginProcessKey: " + err.Error())
	}

	// Sollte der Schlüssel bererits verwendet werden, wird der Vorgang abgebrochen
	if !is_ok {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewLoginProcessKey: aborted, key double using not allowed")
	}

	// Es wird geprüft ob der Benutzer berechtigt ist sich anzumelden
	user_authed, user_granted, err := _validateUserCredentialsPKeyAndStartLoginProcess(obj, prep_credt_pkey, service_data)
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewLoginProcessKey: A" + err.Error())
	}

	// Sollte der Benutzer nicht berechtigt sein, wird der Vorgang abgebrochen
	if !user_authed || !user_granted {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewLoginProcessKey: y: operation for user not granted")
	}

	// Es wird ein neuer Sitzungseintrag in der Datenbank erzeugt
	_, err = obj.db.Exec(SQLITE_WRITE_NEW_LOGIN_PROCESS, user_db_id, service_data.DbServiceId, pre_session_pkey, key_pair.PrivateKey, current_time, service_data.DbServiceUserId, session_req.DbEntryId, -2)
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("CreateNewLoginProcessKey: " + err.Error())
	}

	// Der Threadlock wird freigegeben
	obj.lock.Unlock()

	// Das Rückgabe Objekt wird erzeugt
	result_obj := new(base.LoginProcessKeyCreationDbResult)
	result_obj.PrivateLoginProcessClientKey = key_pair.PrivateKey

	// Die Daten werden zurückgegeben
	return result_obj, nil
}
