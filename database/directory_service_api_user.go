package database

import (
	"fmt"
	"strings"
	"time"

	"github.com/fluffelpuff/HyperDirectory/base"
)

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
Wird verwendet um zu überprüfen ob der Direcotry Service API-User exestiert und aktiv ist
*/
func _AuthAndValidateDirectoryAPIUser(db *Database, pre_finger_print string, session_req base.RequestMetaDataSession) (bool, error) {
	var dsid int64
	var dsauid int64

	if err := db.db.QueryRow(SQLITE_CHECK_SERVICE_API_USER_CREDENTIALS, base.PrepareText(pre_finger_print)).Scan(&dsid, &dsauid); err != nil {
		if err.Error() != "sql: no rows in result set" {
			return false, fmt.Errorf("_AuthAndValidateDirectoryAPIUser: 1:" + err.Error())
		}
		return false, nil
	}

	return dsid > int64(0) && dsauid > int64(0), nil
}

func (obj *Database) AuthAndValidateDirectoryAPIUser(pre_finger_print string, session_req base.RequestMetaDataSession) (bool, error) {
	// Es wird geprüft ob der Token 64 Zeichen lang ist
	is_validate_finger_print, pre_finger_print := validateCertFingerprintDBEntry(pre_finger_print)
	if !is_validate_finger_print {
		return false, fmt.Errorf("AuthAndValidateDirectoryAPIUser: invalid fingerprint")
	}

	// Der Threadlock wird ausgeführt
	obj.lock.Lock()

	// Die Eigentliche Funktion wird aufgeruden
	check_result, err := _AuthAndValidateDirectoryAPIUser(obj, pre_finger_print, session_req)
	if err != nil {
		obj.lock.Unlock()
		return false, fmt.Errorf("AuthAndValidateDirectoryAPIUser: 1: " + err.Error())
	}

	// Der Threadlock wird freigegeben
	obj.lock.Unlock()

	// Die Daten werden zurückgegeben
	return check_result, nil
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
