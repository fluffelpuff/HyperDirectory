package database

import (
	"fmt"
	"time"

	"github.com/fluffelpuff/HyperDirectory/base"
)

/*
Wird verwendet um einen Request in die Datenbank zu schreiben
*/
func (obj *Database) OpenNewRequestEntryAndGetId(request_data *base.RequestMetaData, function_name string, proxy_pass bool) (*base.RequestMetaDataSession, error) {
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
	resturn := base.RequestMetaDataSession{DbEntryId: add_req_id}

	// Der ThreadLock wird freigegeben
	obj.lock.Unlock()

	// Die DirectoryServiceProcess Daten werden zurückgegben
	return &resturn, nil
}

/*
Wird verwendet um einen Dienste API-Benutzer zu Authentifizieren
*/
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
