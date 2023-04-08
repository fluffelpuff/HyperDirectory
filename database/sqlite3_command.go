package database

// Dieser befehl wird verwendet um zu überprüfen ob eine E-Mail Adresse korrekt ist
var SQLITE_CHECK_EMAIL_IN_DB = `
SELECT COUNT(*) FROM email_addresses WHERE email_addresses.email_match_hash == ? AND email_addresses.active == 1
`

// Dieser befehl wird verwendet um zu überprüfen ob der Schlüssel bereits in der Datenbank vorhanden ist
var SQLITE_CHECK_PKEY_IKNOWN = `
SELECT COUNT(*) FROM email_pw_login_credentials WHERE email_pw_login_credentials.owner_pkey == ? AND email_pw_login_credentials.active == 1
`

// Dieser befehl wird verwendet um zu überprüfen ob es bereites einen Benutzer mit dem Entsprechenden Masterkey gibt
var SQLITE_CHECK_USER_WITH_MASTER_PKEY_EXIST = `
SELECT COUNT(*) FROM users WHERE users.master_pkey == ? AND users.active == 1
`

// Dieser befehl wird verwendet um einen neuen nicht Root Benutzer zu erstellen
var SQLITE_CREATE_NEW_NONE_ROOT_USER = `
INSERT INTO "main"."users" ("created_at", "active", "is_root", "master_pkey", "gender", "created_by_user_id", "created_by_request_id", "created_by_service_id_user") VALUES (?, ?, '0', ?, ?, ?, ?, ?);
`

// Dieser befehl wird verwendet um zu überprüfen ob die Services API Userdaten korrekt sind
var SQLITE_CHECK_SERVICE_API_USER_CREDENTIALS = `
SELECT dsid, dsauid FROM directory_service_api_users WHERE cert_fingerprint_sha256 == ? AND active == 1 LIMIT 1
`

// Dieser befehl wird verwendet um alle Berechtigungen für den Aktuellen Services API User abzurufen
var SQLITE_GET_ALL_SERVICES_API_USER_REMISSIONS = `
SELECT value FROM directory_service_api_user_permissions WHERE directory_service_api_user_permissions.dsauid == ? AND directory_service_api_user_permissions.active == 1
`

// Dieser befehl wird verwendet um einen Service API-User Request in der Datenbank zu speichern
var SQLITE_WRITE_NEW_SESSION_DATA = `
INSERT INTO "main"."directory_services_api_user_requests_start" ("dsauid", "user_agent", "host", "accept", "encodings", "connection", "content_length", "content_type", "source_ip", "source_port", "function_name", "created_at", "request_id") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`

// Dieser befehl wird verwendet um eine E-Mail Adresse hinzuzufügen
var SQLITE_WRITE_EMAIL_ADDRESS = `
INSERT INTO "main"."email_addresses" ("uid", "email_address", "email_match_hash", "active", "created_at", "created_by_service_id_user", "created_by_request_id", "created_by_user_id") VALUES (?, ?, ?, ?, ?, ?, ?, ?);
`

// Dieser befehl wird verwendet um Login Credentails zu schreiben
var SQLITE_WRITE_LOGIN_CREDENTIALS = `
INSERT INTO "main"."email_pw_login_credentials" ("uid", "active", "emid", "created_at", "owner_pkey", "password_user_enc", "master_key_user_enc", "created_by_service_id_user", "created_by_request_id", "created_by_user_id") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`

// Wird verwendet um einen Request in die Datenbank zu schreiben
var SQLITE_WRITE_REQUEST_START = `
INSERT INTO "main"."request_starts" ("user_agent", "host", "accept", "encodings", "connection", "content_length", "content_type", "source_ip", "source_port", "function_name", "created_at") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`

// Wird verwendet um einen Vornamen in die Datenbank zu schreiben
var SQLITE_WRITE_FIRSTNAME = `
INSERT INTO "main"."first_names" ("first_name", "created_at", "hight", "uid", "active", "created_by_service_id_user", "created_by_request_id", "created_by_user_id") VALUES (?, ?, ?, ?, ?, ?, ?, ?);
`

// Wird verwendet um einen Nachnamen in die Datenbank zu schreiben
var SQLITE_WRITE_LASTNAME = `
INSERT INTO "main"."last_names" ("last_name", "created_at", "active", "uid", "hight", "created_by_service_id_user", "created_by_request_id", "created_by_user_id") VALUES (?, ?, ?, ?, ?, ?, ?, ?);
`

// Wird verwendet um die Gruppen abzurufen für welche der Service API-User berechtigt ist die Mitgliedschaft zu eines Benutzer hinzuzufügen
var SQLITE_GET_SET_GROUP_PREMITTEDET_GROUPS_EXPLICIT = `
SELECT 
       user_groups_directory_service_api_user_premissions.set_group_membership_premission,
       directory_service_api_users.dsauid,
       directory_service_api_users.dsid,
       user_groups.name,
       user_groups.gid
FROM 
	directory_service_api_users
	JOIN user_groups_directory_services_accesses ON user_groups_directory_services_accesses.directory_service_id == directory_service_api_users.dsid
	JOIN user_groups ON user_groups.gid == user_groups_directory_services_accesses.user_group_id
	JOIN user_groups_directory_service_api_user_premissions ON user_groups_directory_service_api_user_premissions.user_group_id == user_groups.gid
WHERE
	user_groups_directory_service_api_user_premissions.set_group_membership_premission == ? AND
	user_groups_directory_service_api_user_premissions.active == 1 AND
	user_groups_directory_services_accesses.active == 1 AND
	directory_service_api_users.dsauid == ? AND 
	directory_service_api_users.active == 1 AND 
	user_groups.name in (%s) AND
	user_groups.active == 1
GROUP BY
	user_groups.gid
`
