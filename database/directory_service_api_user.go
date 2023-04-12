package database

import (
	"fmt"
	"strings"

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
