package database

import (
	"fmt"
	"time"

	"github.com/fluffelpuff/HyperDirectory/base"
	lunasockets "github.com/fluffelpuff/LunaSockets"
)

// DEPRECATED: This function is deprecated and should not be used.
// ValidateDirectoryServiceUserPremissionAndStartProcess should be used instead.
func (obj *Database) ValidateDirectoryAPIUserAndGetProcessId(verify_cert_fingerprint_unp string, user_agent string, host string, accept string, encodings string, connection string, clen string, content_type string, source_ip string, source_port string, function_name string, session_req base.RequestMetaDataSession) (bool, *base.DirectoryServiceProcess, error) {
	// Es wird geprüft ob der Token 64 Zeichen lang ist
	is_validate_finger_print, pre_finger_print := validateCertFingerprintDBEntry(verify_cert_fingerprint_unp)
	if !is_validate_finger_print {
		return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: invalid fingerprint")
	}

	// Der Threadlock wird ausgeführt
	obj.lock.Lock()

	// Es wird geprüft ob der API Benutzer exestiert
	var dsid int64
	var dsauid int64
	if err := obj.db.QueryRow(SQLITE_CHECK_SERVICE_API_USER_CREDENTIALS, base.PrepareText(pre_finger_print)).Scan(&dsid, &dsauid); err != nil {
		obj.lock.Unlock()
		if err.Error() != "sql: no rows in result set" {
			return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: 1:" + err.Error())
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
	request_add_result, err := obj.db.Exec(SQLITE_WRITE_NEW_SESSION_DATA, dsauid, user_agent, host, accept, encodings, connection, clen, content_type, source_ip, source_port, function_name, current_time.Unix(), session_req.DbEntryId)
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
	resturn := base.DirectoryServiceProcess{DatabaseId: add_req_id, StartingTime: current_time, DbServiceUserId: dsauid, DbServiceId: dsid}

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
Wird verwendet um einen Dienste API-Benutzer zu Authentifizieren und eine Live Sitzung zu erstellen
*/
func (obj *Database) ValidateDirectoryAPIUserAndGetLiveSession(verify_cert_fingerprint_unp string, user_agent string, host string, accept string, encodings string, connection string, clen string, content_type string, source_ip string, source_port string, source_live_session *uint64) (bool, *base.LiveRPCSession, error) {
	// Es wird geprüft ob der Token 64 Zeichen lang ist
	is_validate_finger_print, pre_finger_print := validateCertFingerprintDBEntry(verify_cert_fingerprint_unp)
	if !is_validate_finger_print {
		return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetLiveSession: invalid fingerprint")
	}

	// Der Threadlock wird ausgeführt
	obj.lock.Lock()

	// Es wird geprüft ob der API Benutzer exestiert
	var dsid int64
	var dsauid int64
	if err := obj.db.QueryRow(SQLITE_CHECK_SERVICE_API_USER_CREDENTIALS, base.PrepareText(pre_finger_print)).Scan(&dsid, &dsauid); err != nil {
		obj.lock.Unlock()
		if err.Error() != "sql: no rows in result set" {
			return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetLiveSession: 1:" + err.Error())
		}
		return false, nil, nil
	}
	if dsauid == 0 {
		obj.lock.Unlock()
		return false, nil, nil
	}

	// Es wird ein Eintrag für diesen Request erstellt
	request_add_result, err := obj.db.Exec(SQLITE_WRITE_NEW_LIVE_SESSION_DATA, dsauid, user_agent, host, accept, encodings, connection, clen, content_type, source_ip, source_port, time.Now().Unix())
	if err != nil {
		obj.lock.Unlock()
		return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetLiveSession: " + err.Error())
	}

	// Die ID des neuen Eintrages wird ermittelt
	add_req_id, err := request_add_result.LastInsertId()
	if err != nil {
		obj.lock.Unlock()
		return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetLiveSession: " + err.Error())
	}

	// Der Threadlock wird freigegeben
	obj.lock.Unlock()

	// Es wird ein neues Rückgabe Objekt erstellt
	new_result := new(base.LiveRPCSession)
	new_result.CertFingerprint = pre_finger_print
	new_result.DbSessionId = add_req_id

	return true, new_result, nil
}

/*
Wird verwendet um eine Offene Service API-Benutzer Sitzung zu schließen
*/
func (obj *Database) CloseDirectoryAPIUserLiveSession(session_ptr *base.LiveRPCSession, err error, warning error) error {
	return nil
}

/*
Erstellt eine neue Sitzung und überprüft ob der Aktuelle Direcotry Service User für diese Aktion berechtigt ist
*/
func (obj *Database) ValidateDirectoryServiceUserPremissionAndStartProcess(session_data *base.LiveRPCSession, header_data *lunasockets.HeaderData, function_name string, proxy_pass bool) (bool, *base.LiveRPCSessionProcess, error) {
	// Die Aktuelle sowie die Ablaufzeit wird ermittelt
	current_time := time.Now()

	// Der Threadlock wird ausgeführt
	obj.lock.Lock()

	// Es wird geprüft ob der API Benutzer exestiert
	var dsid int64
	var dsauid int64
	if err := obj.db.QueryRow(SQLITE_CHECK_SERVICE_API_USER_CREDENTIALS, base.PrepareText(session_data.CertFingerprint)).Scan(&dsid, &dsauid); err != nil {
		obj.lock.Unlock()
		if err.Error() != "sql: no rows in result set" {
			return false, nil, fmt.Errorf("ValidateDirectoryServiceUserPremissionAndStartSession: 1:" + err.Error())
		}
		return false, nil, nil
	}
	if dsauid == 0 {
		obj.lock.Unlock()
		return false, nil, nil
	}

	// Es wird ein Eintrag für diesen Request erstellt
	request_add_result, err := obj.db.Exec(SQLITE_WRITE_REQUEST_START, header_data.UserAgent, header_data.Host, header_data.Accept, header_data.AcceptEncoding, header_data.Connection, header_data.ContentLength, header_data.ContentType, header_data.SourceIp, header_data.SourcePort, function_name, current_time.Unix())
	if err != nil {
		obj.lock.Unlock()
		return false, nil, fmt.Errorf("ValidateDirectoryServiceUserPremissionAndStartSession: " + err.Error())
	}

	// Die ID des neuen Eintrages wird ermittelt
	add_req_id, err := request_add_result.LastInsertId()
	if err != nil {
		obj.lock.Unlock()
		return false, nil, fmt.Errorf("ValidateDirectoryServiceUserPremissionAndStartSession: " + err.Error())
	}

	// Es werden alle berechtigungen für diesen Benutzer abgerufen
	rows, err := obj.db.Query(SQLITE_GET_ALL_SERVICES_API_USER_REMISSIONS, dsauid)
	if err != nil {
		obj.lock.Unlock()
		return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: " + err.Error())
	}

	// Gibt an ob die passende Fnktion in der berechtigunsliste gefunden wurde
	has_found_prem := false

	// Lesen Sie die Ergebnisse der Abfrage
	for rows.Next() {
		// Es wird versucht den Aktuellen Wert auszulesen
		var value string
		err = rows.Scan(&value)
		if err != nil {
			obj.lock.Unlock()
			return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: " + err.Error())
		}

		// Es wird geprüft ob die Gewühnschte Funktion vorhanden ist
		if value == function_name {
			has_found_prem = true
			break
		}
	}

	// Die Anfrage wird aus Sicherheitsgründen wieder geschlossen
	if err := rows.Close(); err != nil {
		obj.lock.Unlock()
		return false, nil, fmt.Errorf("ValidateDirectoryAPIUserAndGetProcessId: " + err.Error())
	}

	// Der ThreadLock wird freigegeben
	obj.lock.Unlock()

	// Die Aktuelle Zeit wird neu Ermittelt
	final_current_time := time.Now()

	// Der Rückgabewert wird erstellt
	result_object := base.LiveRPCSessionProcess{DbSessionId: add_req_id, StartTimestamp: uint64(current_time.Unix()), EndTimestamp: uint64(final_current_time.Unix()), Session: session_data}

	// Sollte der Benutzer nicht berechtigt sein, wird der Vogang abgebrochen
	if !has_found_prem {
		msg := "user has not premissions"
		return false, nil, obj.CloseEntryRequestProcess(&result_object, &msg, nil)
	}

	// Die DirectoryServiceProcess Daten werden zurückgegben
	return true, &result_object, nil
}

/*
Wird verwendet um einen Offenen Session Request in der Datenbank zu schlißen
*/
func (obj *Database) CloseEntryRequestProcess(request_session *base.LiveRPCSessionProcess, warning *string, errort error) error {
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
	if err := obj.db.QueryRow(SQLITE_GET_META_REQUEST_CLOSED, request_session.DbSessionId).Scan(&is_open); err != nil {
		obj.lock.Unlock()
		return err
	}
	if is_open != "OPEN" {
		obj.lock.Unlock()
		return fmt.Errorf("CloseEntrySessionRequest: ")
	}

	// Die Request Session wird ohne fehler und oder warnung geschlossen
	if warning == nil && errort == nil {
		_, err := obj.db.Exec(SQLITE_WRITE_REQUEST_SESSION_CLOSE, request_session.DbSessionId, current_time.Unix())
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
	_, err := obj.db.Exec(SQLITE_WRITE_REQUEST_SESSION_CLOSE_WITH_WARNING_OR_ERROR, request_session.DbSessionId, warning_str, errors_str, current_time.Unix())
	if err != nil {
		obj.lock.Unlock()
		return fmt.Errorf("CloseEntrySessionRequest: " + err.Error())
	}

	// Der Threadlock wird freigegeben
	obj.lock.Unlock()

	// Der Vorgang wurde erfolgreich durchgeführt
	return nil
}
