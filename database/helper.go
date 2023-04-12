package database

import "fmt"

/*
Wird verwendet um zu überprüfen ob ein Schlüssel bereits verwendet wird
*/
func _checkIsKeyInDb(db *Database, public_key string, service_id uint64) (bool, error) {
	// Es wird geprüft ob der Schlüssel in Login Prozess Tabelle vorhanden ist
	var has_found_in_login_process_table string
	if err := db.db.QueryRow(SQLITE_GET_KEY_USED_BY_LOGIN_PROCESS, service_id, public_key).Scan(&has_found_in_login_process_table); err != nil {
		return false, fmt.Errorf("_checkIsKeyInDb: 1: " + err.Error())
	}

	// Es wird gpeüft ob der Schlüssel in Sitzungstabelle verwendet wird
	var has_found_in_session_table string
	if err := db.db.QueryRow(SQLITE_GET_KEY_USED_BY_LOGIN_SESSION, service_id, public_key).Scan(&has_found_in_session_table); err != nil {
		return false, fmt.Errorf("_checkIsKeyInDb: 1: " + err.Error())
	}

	// Es wird geprüft ob der Schlüssel in der Schlüsselpaartabelle verwendet wird
	var has_found_key_pairs string
	if err := db.db.QueryRow(SQLITE_GET_KEY_USED_BY_KEY_PAIR, public_key).Scan(&has_found_key_pairs); err != nil {
		return false, fmt.Errorf("_checkIsKeyInDb: 1: " + err.Error())
	}

	// Es wird geprüft ob der Schlüssel als Benutzer Masterkey bereits verwendet wird
	var has_found_as_master_pubkey string
	if err := db.db.QueryRow(SQLITE_GET_KEY_USED_BY_USER_AS_MSATER_KEY, public_key).Scan(&has_found_as_master_pubkey); err != nil {
		return false, fmt.Errorf("_checkIsKeyInDb: 1: " + err.Error())
	}

	fmt.Println(has_found_in_login_process_table, has_found_in_session_table, has_found_key_pairs, has_found_as_master_pubkey)

	// Es wird geprüft ob alle Vorgänge erfolgreich waren
	if has_found_in_login_process_table != "GRANTED" || has_found_in_session_table != "GRANTED" || has_found_key_pairs != "GRANTED" || has_found_as_master_pubkey != "GRANTED" {
		return false, nil
	}

	// Der Schlüssel wird noch nicht verwendet
	return true, nil
}
