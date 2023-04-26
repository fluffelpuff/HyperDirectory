package database

import (
	"fmt"
	"time"

	"github.com/fluffelpuff/HyperDirectory/base"
)

// DEPRECATED: This function is deprecated and should not be used.
// CloseEntryRequestProcess should be used instead.
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
Wird verwendet um einen Request in die Datenbank zu schreiben
*/
func (obj *Database) OpenNewEntrySessionRequet(request_data *base.RequestMetaData, function_name string, proxy_pass bool) (*base.RequestMetaDataSession, error) {
	// Der Threadlock wird ausgeführt
	obj.lock.Lock()

	// Die Aktuelle sowie die Ablaufzeit wird ermittelt
	current_time := time.Now()

	// Es wird ein Eintrag für diesen Request erstellt
	request_add_result, err := obj.db.Exec(SQLITE_WRITE_REQUEST_START, request_data.UserAgent, request_data.Domain, request_data.Accept, request_data.Encodings, request_data.Connection, request_data.ContentLength, request_data.ContentType, request_data.SourceIp, request_data.SourcePort, function_name, current_time.Unix())
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("OpenNewEntrySessionRequet: " + err.Error())
	}

	// Die ID des neuen Eintrages wird ermittelt
	add_req_id, err := request_add_result.LastInsertId()
	if err != nil {
		obj.lock.Unlock()
		return nil, fmt.Errorf("OpenNewEntrySessionRequet: " + err.Error())
	}

	// Das Rückgabeobjekt wird erstellt
	resturn := base.RequestMetaDataSession{DbEntryId: add_req_id}

	// Der ThreadLock wird freigegeben
	obj.lock.Unlock()

	// Die DirectoryServiceProcess Daten werden zurückgegben
	return &resturn, nil
}
