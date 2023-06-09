package database

import (
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

// Dieser befehl wird verwendet um alle verfügbaren Tabellen aufzulisten
var sql_list_all_tabels = `
SELECT name FROM sqlite_master  WHERE type='table';
`

// Dieser befehel erstellt die Tabelle für E-Mail Adressen
var sql_create_email_address_table = `
CREATE TABLE "email_addresses" (
	"emid"	INTEGER,
	"uid"	INTEGER,
	"email_address"	TEXT,
	"email_match_hash"	TEXT,
	"active"	INTEGER,
	"created_at"	INTEGER,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	PRIMARY KEY("emid" AUTOINCREMENT)
);
`

// Dieser befehl erstellt die Tabelle für Anmeldeinformationen
var sql_create_login_credentials = `
CREATE TABLE "email_pw_login_credentials" (
	"lcid"	INTEGER UNIQUE,
	"uid"	INTEGER,
	"active"	INTEGER,
	"emid"	INTEGER,
	"created_at"	INTEGER,
	"owner_pkey"	TEXT,
	"password_user_enc"	TEXT,
	"master_key_user_enc"	TEXT,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	PRIMARY KEY("lcid" AUTOINCREMENT)
);
`

// Dieser befehl erstellt die Tabelle für die Benutzer
var sql_create_user_table = `
CREATE TABLE "users" (
	"uid"	INTEGER,
	"created_at"	INTEGER,
	"active"	INTEGER,
	"is_root"	INTEGER DEFAULT 0,
	"master_pkey"	TEXT,
	"gender"	TEXT,
	"created_by_user_id"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_service_id_user"	INTEGER,
	PRIMARY KEY("uid" AUTOINCREMENT)
);
`

// Dieser befehl erstellt die Tabelle für die Benutzergruppen
var sql_create_user_group_table = `
CREATE TABLE "user_groups" (
	"gid"	INTEGER UNIQUE,
	"name"	TEXT,
	"active"	INTEGER,
	"fqdn_name"	TEXT,
	"description"	TEXT,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	PRIMARY KEY("gid" AUTOINCREMENT)
);
`

// Dieser befehl erstellt die Tabelle für die Benutzergruppen Mitgliedschaften
var sql_create_user_group_member_table = `
CREATE TABLE "user_group_member" (
	"ugmid"	INTEGER,
	"uid"	INTEGER,
	"gid"	INTEGER,
	"active"	INTEGER,
	"service_id"	INTEGER,
	"created_at"	INTEGER,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	PRIMARY KEY("ugmid" AUTOINCREMENT)
);
`

// Dieser befehl erstetllt eine Tabelle für die Vornamen
var sql_create_first_name_table_ = `
CREATE TABLE "first_names" (
	"fnid"	INTEGER UNIQUE,
	"first_name"	TEXT,
	"created_at"	INTEGER,
	"hight"	INTEGER,
	"uid"	INTEGER,
	"active"	INTEGER,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	PRIMARY KEY("fnid" AUTOINCREMENT)
);
`

// Dieser befehl erstellt eine Tabelle für die Nachnamen
var sql_create_last_name_table = `
CREATE TABLE "last_names" (
	"lnid"	INTEGER UNIQUE,
	"last_name"	TEXT,
	"created_at"	INTEGER,
	"active"	INTEGER,
	"uid"	INTEGER,
	"hight"	INTEGER,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	PRIMARY KEY("lnid" AUTOINCREMENT)
);
`

// Dieser befehl erstellt eine Tabelle für die Schlüsselpaare
var sql_create_key_pairs_table = `
CREATE TABLE "key_pairs" (
	"kpid"	INTEGER UNIQUE,
	"uid"	INTEGER,
	"active"	INTEGER,
	"public_key_hash"	TEXT,
	"public_key"	TEXT,
	"private_key"	TEXT,
	"type"	TEXT,
	"is_ssh"	TEXT,
	"created_at"	INTEGER,
	PRIMARY KEY("kpid" AUTOINCREMENT)
);`

// Dieser befehl wird verwendet um die Tabelle für die Vefügbaren Dienste zu Registrieren
var sql_create_new_service_table = `
CREATE TABLE "directory_service_api_users" (
	"dsauid"	INTEGER UNIQUE,
	"dsid"	INTEGER,
	"cert_fingerprint_sha256"	TEXT,
	"active"	INTEGER,
	"created_at"	INTEGER,
	"created_by_uid"	INTEGER,
	PRIMARY KEY("dsauid" AUTOINCREMENT)
);
`

// Dieser befehl wird verwendet um die Tabelle für die Service User API Requests zu erstellen
var sql_services_user_api_request = `
CREATE TABLE "directory_services_api_user_requests" (
	"dsaurid"	INTEGER UNIQUE,
	"dsauid"	INTEGER,
	"user_agent"	TEXT,
	"host"	TEXT,
	"accept"	TEXT,
	"encodings"	TEXT,
	"connection"	TEXT,
	"content_length"	TEXT,
	"content_type"	TEXT,
	"source_ip"	TEXT,
	"source_port"	TEXT,
	"function_name"	TEXT,
	"created_at"	INTEGER,
	"expiry_time"	INTEGER,
	"request_id"	INTEGER,
	PRIMARY KEY("dsaurid" AUTOINCREMENT)
);
`

// Dieser befehl wird verwendet um die Tabelle für Berechtigungen zu erstellen
var sql_serives_user_premissions = `
CREATE TABLE "directory_service_api_user_permissions" (
	"dsaupid"	INTEGER UNIQUE,
	"dsauid"	INTEGER,
	"value"	INTEGER,
	"active"	INTEGER,
	"created_at"	INTEGER,
	"created_by"	INTEGER,
	PRIMARY KEY("dsaupid" AUTOINCREMENT)
);
`

// Dieser befehl wird verwendet um die Tabelle für die Requests zu erstellen
var sql_request_table = `
CREATE TABLE "request_starts" (
	"reqid"	INTEGER UNIQUE,
	"user_agent"	TEXT,
	"host"	TEXT,
	"accept"	TEXT,
	"encodings"	TEXT,
	"connection"	TEXT,
	"content_length"	TEXT,
	"content_type"	TEXT,
	"source_ip"	TEXT,
	"source_port"	TEXT,
	"function_name"	TEXT,
	"created_at"	INTEGER,
	PRIMARY KEY("reqid" AUTOINCREMENT)
);`

// Dieser befehl erstellt die Tabelle für die Gruppenzuweisungen in die Directory Dienste
var sql_directory_services_user_groups_access_table = `
CREATE TABLE "user_groups_directory_services_accesses" (
	"augidsid"	INTEGER,
	"directory_service_id"	INTEGER,
	"created_at"	INTEGER,
	"active"	INTEGER,
	"user_group_id"	INTEGER,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	"directory_service_user_id"	INTEGER,
	PRIMARY KEY("augidsid" AUTOINCREMENT)
);
`

// Erstellt die Tabelle für die
var sql_user_groups_directory_service_api_user_premissions_table = `
CREATE TABLE "user_groups_directory_service_api_user_premissions" (
	"ugdsaupid"	INTEGER,
	"directory_service_user_id"	INTEGER,
	"set_group_membership_premission"	INTEGER,
	"active"	INTEGER,
	"created_at"	INTEGER,
	"user_group_id"	INTEGER,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	PRIMARY KEY("ugdsaupid" AUTOINCREMENT)
);
`

// Erstellt die Tabelle für die Zuordnung von Benutzern zu Direcotry Services
var sql_user_member_of_directory_service_table = `
CREATE TABLE "user_directory_service_members" (
	"udsmid"	INTEGER,
	"user_id"	INTEGER,
	"directory_service_id"	INTEGER,
	"user_directory_id"	TEXT,
	"active"	INTEGER,
	"created_at"	INTEGER,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	PRIMARY KEY("udsmid" AUTOINCREMENT)
);
`

// Erstellt die Datenbank für die Nutzer Sitzungen
var sql_create_user_session_table = `
CREATE TABLE "user_sessions" (
	"usid"	INTEGER,
	"service_id"	INTEGER,
	"user_id"	INTEGER,
	"device_id"	INTEGER,
	"created_at"	INTEGER,
	"client_pkey"	TEXT,
	"server_privkey"	INTEGER,
	"session_id_chsum"	INTEGER UNIQUE,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	"created_by_login_process_id"	INTEGER,
	PRIMARY KEY("usid" AUTOINCREMENT)
);
`

// Erstellt die Tabelle für das Schließen von Requests
var sql_create_meta_request_closed_table = `
CREATE TABLE "request_closers" (
	"rstid"	INTEGER,
	"reqid"	INTEGER,
	"error"	TEXT,
	"warning"	TEXT,
	"created_at"	INTEGER,
	PRIMARY KEY("rstid" AUTOINCREMENT)
);
`

// Erstellt die Tabelle für das Starten von Benutzer Sitzungen innerhalb eines Dienstes
var user_session_starting_request_table = `
CREATE TABLE "user_session_starting_request" (
	"ussr"	INTEGER,
	"user_id"	INTEGER,
	"service_id"	INTEGER,
	"one_time_client_session_pkey"	TEXT,
	"one_time_server_session_privkey"	TEXT,
	"one_time_server_session_pkey"	TEXT,
	"created_at"	INTEGER,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	PRIMARY KEY("ussr" AUTOINCREMENT)
);
`

// Erstellt die Tabelle für die Directory Service Filter nach Nutzer
var sqlite_create_user_directory_filter_table = `
CREATE TABLE "user_directory_service_filter" (
	"udsfid"	INTEGER,
	"filter"	TEXT,
	"directory_service_id"	INTEGER,
	"directory_service_api_user_id"	INTEGER DEFAULT -1,
	"created_at"	INTEGER,
	"active"	INTEGER,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	PRIMARY KEY("udsfid" AUTOINCREMENT)
);
`

// Erstellt die Tabelle für die Einzelnene Benutzer Rechte
var sqlite_create_user_permissions_table = `
CREATE TABLE "user_permissions" (
	"upid"	INTEGER,
	"permission"	TEXT,
	"user_id"	INTEGER,
	"directory_service_id"	INTEGER,
	"active"	INTEGER,
	"created_at"	INTEGER,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	PRIMARY KEY("upid" AUTOINCREMENT)
);
`

// Erstellt die Tabelle für Grupppenrechte
var sqlite_create_user_group_permissions_table = `
CREATE TABLE "user_group_permissions" (
	"ugpid"	INTEGER,
	"group_id"	INTEGER,
	"directory_service_id"	INTEGER,
	"name"	INTEGER,
	"created_at"	INTEGER,
	"active"	INTEGER,
	"created_by_service_id_user"	INTEGER,
	"created_by_request_id"	INTEGER,
	"created_by_user_id"	INTEGER,
	PRIMARY KEY("ugpid" AUTOINCREMENT)
);
`

// Erstellt die Tabelle für die Directory API User Live Sessions
var sqlite_directory_api_user_live_sessions_start_table = `
CREATE TABLE directory_services_api_user_live_session_start (
	dsass INTEGER PRIMARY KEY AUTOINCREMENT,
	dsauid INTEGER,
	user_agent TEXT,
	host TEXT,
	accept TEXT,
	encodings TEXT,
	connection TEXT,
	content_length INTEGER,
	content_type TEXT,
	source_ip INTEGER,
	source_port INTEGER,
	created_at DATETIME
)
`

// Stellt das Datenbank Objekt dar
type Database struct {
	privKey *string
	lock    sync.Mutex
	db      *sql.DB
}

// Erstellt eine neue SQL-Lite basierte Datenbank
func CreateNewSQLiteBasedDatabase(file_path string, local_priv_key *string) (*Database, error) {
	// Es wird versucht die SQL Datei zu laden
	db, err := sql.Open("sqlite3", file_path)
	if err != nil {
		return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
	}

	// Es wird geprüft ob die Login Credentials Tabelle verfügbar ist
	response, err := db.Query(sql_list_all_tabels)
	if err != nil {
		return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
	}

	// Es wird geprüft ob die benötigten Tabellen vorhanden sind
	var name string
	email_addresses, directory_service_api_users, user_directory_service_members := false, false, false
	login_creds, users, user_groups, user_group_member, first_names := false, false, false, false, false
	key_pairs, last_names, directory_services_api_user_requests := false, false, false
	directory_service_api_user_permissions, requests, user_groups_directory_services_accesses := false, false, false
	user_groups_directory_service_api_user_premissions, user_sessions, request_closers := false, false, false
	user_session_starting_request, user_directory_service_filter, user_permissions := false, false, false
	user_group_permissions, directory_services_api_user_live_session_start := false, false
	for response.Next() {
		// Der Name wird geprüft
		err = response.Scan(&name)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}

		// Es wird geprüft welche Tabelle vorhanden ist
		if name == "email_addresses" {
			email_addresses = true
		} else if name == "email_pw_login_credentials" {
			login_creds = true
		} else if name == "users" {
			users = true
		} else if name == "user_groups" {
			user_groups = true
		} else if name == "user_group_member" {
			user_group_member = true
		} else if name == "first_names" {
			first_names = true
		} else if name == "last_names" {
			last_names = true
		} else if name == "key_pairs" {
			key_pairs = true
		} else if name == "directory_service_api_users" {
			directory_service_api_users = true
		} else if name == "directory_services_api_user_requests" {
			directory_services_api_user_requests = true
		} else if name == "directory_service_api_user_permissions" {
			directory_service_api_user_permissions = true
		} else if name == "request_starts" {
			requests = true
		} else if name == "user_groups_directory_services_accesses" {
			user_groups_directory_services_accesses = true
		} else if name == "user_groups_directory_service_api_user_premissions" {
			user_groups_directory_service_api_user_premissions = true
		} else if name == "user_directory_service_members" {
			user_directory_service_members = true
		} else if name == "user_sessions" {
			user_sessions = true
		} else if name == "request_closers" {
			request_closers = true
		} else if name == "user_session_starting_request" {
			user_session_starting_request = true
		} else if name == "user_directory_service_filter" {
			user_directory_service_filter = true
		} else if name == "user_permissions" {
			user_permissions = true
		} else if name == "user_group_permissions" {
			user_group_permissions = true
		} else if name == "directory_services_api_user_live_session_start" {
			directory_services_api_user_live_session_start = true
		}
	}

	// Es wird versucht den Aktuellen Cursor zu schließen
	if db_err := response.Close(); db_err != nil {
		return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + db_err.Error())
	}

	// Sollte keine Directory API User Live Sessions Tabelle vorhanden sein, wird diese Hinzugefügt
	if !directory_services_api_user_live_session_start {
		_, err = db.Exec(sqlite_directory_api_user_live_sessions_start_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Directory API User Live Sessions table created")
	}

	// Sollte keine User Groups Permissions Tabelle vorhanden sein, wird diese hinzugefügt
	if !user_group_permissions {
		_, err = db.Exec(sqlite_create_user_group_permissions_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("User Group Permissions table created")
	}

	// Sollte die Users Permissions Tabelle nicht vorhanden sein, wird diese hinzugefügt
	if !user_permissions {
		_, err = db.Exec(sqlite_create_user_permissions_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("User Permissions table created")
	}

	// Sollte die User Directory Service Filter Tabelle nicht vorhanden sein wird diese erzeugt
	if !user_directory_service_filter {
		_, err = db.Exec(sqlite_create_user_directory_filter_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("User Directory Service table created")
	}

	// Sollte die User Session Starting Request Tabelle nicht vorhanden sein wird diese erzeugt
	if !user_session_starting_request {
		_, err = db.Exec(user_session_starting_request_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("User Session Starting Request table created")
	}

	// Sollte die Request Stops Tabelle nicht vorhanden sein wird diese erzeugt
	if !request_closers {
		_, err = db.Exec(sql_create_meta_request_closed_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Request stops table created")
	}

	// Sollte die Directory Tabelle nicht vorhanden sein wird diese erzeugt
	if !directory_service_api_users {
		_, err = db.Exec(sql_create_new_service_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Directory Service API-Users table created")
	}

	// Sollte die E-Mails Tabelle nicht vorhanden sein wird diese erzeugt
	if !email_addresses {
		_, err = db.Exec(sql_create_email_address_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("E-Mail addresses table created")
	}

	// Sollte die Login Credentials Tabelle nicht vorhanden sein wird diese erzeugt
	if !login_creds {
		_, err = db.Exec(sql_create_login_credentials)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Login Credentials table created")
	}

	// Sollte keine Benutzer Tabelle vorhanden sein, so wird diese erstellt
	if !users {
		_, err = db.Exec(sql_create_user_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Users table created")
	}

	// Sollten keine Benutzergruppen Tabelle vorhanden sein, so wird dieser erstellt
	if !user_groups {
		_, err = db.Exec(sql_create_user_group_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Users groups table created")
	}

	// Sollten keine Benutzergruppen Mitglieder Tabelle vorhanden sein, so wird diese erstellt
	if !user_group_member {
		_, err = db.Exec(sql_create_user_group_member_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Users group members table created")
	}

	// Sollte keine Vornamen Tabelle vorhanden sein, so wird diese erstellt
	if !first_names {
		_, err = db.Exec(sql_create_first_name_table_)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Users first names table created")
	}

	// Sollte keine Nachnamen Tabelle vorhanden sein, so wird diese erstellt
	if !last_names {
		_, err = db.Exec(sql_create_last_name_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Users last names table created")
	}

	// Sollten keine Schlüsselpaar Tabelle vorhanden sein, so wird diese erstellt
	if !key_pairs {
		_, err = db.Exec(sql_create_key_pairs_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Users key pairs table created")
	}

	// Sollte keine Services Tabelle vorhanden sein, so wird diese erstellt
	if !directory_services_api_user_requests {
		_, err = db.Exec(sql_services_user_api_request)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Services API User Requests table created")
	}

	// Sollte keine Services API User Premissions Tabelle vorhanden sein, so wird diese erstellt
	if !directory_service_api_user_permissions {
		_, err = db.Exec(sql_serives_user_premissions)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Services API User Premissions table created")
	}

	// Sollte keine Requests Tabelle vorhanden sein, wird diese erstellt
	if !requests {
		_, err = db.Exec(sql_request_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Requests table created")
	}

	// Sollte keine Directory Service API-User Acsess Tabelle vorhanden sein, wird diese erstellt
	if !user_groups_directory_services_accesses {
		_, err = db.Exec(sql_directory_services_user_groups_access_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("User Groups Directory Services Accesses table created")
	}

	// Sollte keine User Groups Directory Service Api User Premissions Tabelle vorhanden sein, wird diese erstellt
	if !user_groups_directory_service_api_user_premissions {
		_, err = db.Exec(sql_user_groups_directory_service_api_user_premissions_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("User Groups Directory Service Api User Premissions table created")
	}

	// Sollte keine Sql User Member of Directory Service Tabelle vorhanden sein, wird dieser erstellt
	if !user_directory_service_members {
		_, err = db.Exec(sql_user_member_of_directory_service_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("Sql User Member of Directory Service table created")
	}

	// Sollte keine Session Tabelle vorhanden sein, wird diese erzeugt
	if !user_sessions {
		_, err = db.Exec(sql_create_user_session_table)
		if err != nil {
			return nil, fmt.Errorf("CreateNewSQLiteBasedDatabase: " + err.Error())
		}
		fmt.Println("User sessions table created")
	}

	// Das Datenbank Objekt wird erzeugt
	db_obj := Database{db: db, privKey: local_priv_key}

	// Die Datenbank wurde erfolgreich geladen
	fmt.Println("Database loaded")
	return &db_obj, nil
}
