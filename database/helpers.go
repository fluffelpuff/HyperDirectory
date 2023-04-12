package database

import (
	"database/sql"
	"fmt"

	"github.com/fluffelpuff/HyperDirectory/base"
)

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

	// Es wird geprüft ob alle Vorgänge erfolgreich waren
	if has_found_in_login_process_table != "GRANTED" || has_found_in_session_table != "GRANTED" || has_found_key_pairs != "GRANTED" || has_found_as_master_pubkey != "GRANTED" {
		return false, nil
	}

	// Der Schlüssel wird noch nicht verwendet
	return true, nil
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
