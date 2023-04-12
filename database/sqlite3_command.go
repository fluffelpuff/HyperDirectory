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
INSERT INTO "main"."directory_services_api_user_requests" ("dsauid", "user_agent", "host", "accept", "encodings", "connection", "content_length", "content_type", "source_ip", "source_port", "function_name", "created_at", "request_id") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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

// Wird verwendet um einem Benutzer mittels Service API-User einer Gruppe zuzuweisen
var SQLITE_WRITE_USER_API_USER_SET_GROUP = `
INSERT INTO user_group_member (gid,  uid,  active,  created_at,  service_id, created_by_service_id_user, created_by_request_id, created_by_user_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
`

// Wird verwendet um den Benutzer einem Directory Service zuzuweisen
var SQLITE_WRITE_SET_USER_MEMBERSHIP_OF_DIRECOTRY_SERVICE = `
INSERT INTO user_directory_service_members (user_id, directory_service_id, user_directory_id, active, created_at, created_by_service_id_user, created_by_request_id, created_by_user_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
`

// Wird verwendet um den Benutzer dem Service zuzuweisen
var SQLITE_CHECK_USER_SERVICES_STATE_AND_MEMBERSHIP = `
SELECT
	CASE WHEN  COUNT(users.uid) >= 1
       THEN 'YES'
       ELSE 'NO'
       END AS user_is_active_service_member
FROM
users
JOIN user_directory_service_members
ON users.uid == user_directory_service_members.user_id
WHERE
	users.uid == ? AND
	users.active == 1 AND
	user_directory_service_members.active == 1 AND
	user_directory_service_members.directory_service_id == ?
`

// Wird verwendet um eine User Session zu erstellen
var SQLITE_WRITE_CREATE_USER_SESSION = `
INSERT INTO user_sessions (user_id, service_id, device_id, created_at, client_pkey, server_privkey, session_id_chsum, created_by_service_id_user, created_by_request_id, created_by_user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`

// Wird verwendet um zu ermitteln ob der Entsprechende Meta Request bereits geschlossen wurde
var SQLITE_GET_META_REQUEST_CLOSED = `
SELECT
	CASE WHEN  COUNT(request_closers.reqid) >= 1
       THEN 'CLOSED'
       ELSE 'OPEN'
       END AS state
FROM
request_starts
JOIN request_closers
ON request_closers.reqid = request_starts.reqid
WHERE request_starts.reqid == ?
`

// Wird verwendet um eine Request Session ohne Warnung und ohne Fehler zu schließen
var SQLITE_WRITE_REQUEST_SESSION_CLOSE = `
INSERT INTO request_closers (reqid, error, warning, created_at) VALUES (?, '', '', ?);
`

// Wird verwendet um eine Fehlermeldung und oder eine Warnung in die Datenbank zu schreiben
var SQLITE_WRITE_REQUEST_SESSION_CLOSE_WITH_WARNING_OR_ERROR = `
INSERT INTO request_closers (reqid, error, warning, created_at) VALUES (?, ?, ?, ?);
`

// Wird verwendet um zu überprüfen ob es einen Aktiven Öffentlichen Schlüssel für diesen Benutzer gibt
// außerdem wird geprüft ob der Benutzer Mitglied des Aktuellen Dienstes ist
var SQLITE_GET_LOGIN_CREDENTIALS_ACCEPTED_BY_PUB_KEY = `
SELECT
	CASE WHEN  COUNT(email_pw_login_credentials.lcid) >= 1
		THEN 'FOUND'
		ELSE 'NOT_FOUND'
	END AS state,
	users.uid
FROM email_pw_login_credentials
JOIN users ON users.uid == email_pw_login_credentials .uid
JOIN user_directory_service_members ON user_directory_service_members.user_id == users.uid
WHERE
	email_pw_login_credentials.owner_pkey == ? AND
	user_directory_service_members.directory_service_id == ? AND
	user_directory_service_members.active == 1 AND
	email_pw_login_credentials.active == 1 AND
	users.active == 1
`

// Wird verwendet um eine neuen Login Vorgang zu erstellen
var SQLITE_WRITE_NEW_LOGIN_PROCESS = `
INSERT INTO user_session_starting_request (user_id, service_id, one_time_client_session_pkey, one_time_server_session_privkey, created_at, created_by_service_id_user, created_by_request_id, created_by_user_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
`

// Wird verwendet um zu ermitteln ob es einen Aktiven Benutzer mit Passenden Login Credentials zu dem Aktuellen Directory Service gibt
var SQLITE_GET_ACTIVE_USER_DIRECTORY_SERVICE_BY_LOGIN_CREDENTIALS = `
SELECT
	CASE WHEN COUNT(email_pw_login_credentials.lcid) >= 1
		THEN 'PERMITTED'
		ELSE 'NOT_PERMITTED'
	END AS allowed_login_creds
FROM email_pw_login_credentials
JOIN users ON users.active == 1 AND users.uid == email_pw_login_credentials.uid
JOIN user_directory_service_members ON user_directory_service_members.active == 1 AND user_directory_service_members.user_id == email_pw_login_credentials.uid
WHERE
	email_pw_login_credentials.owner_pkey == ? AND
	user_directory_service_members.directory_service_id == ? AND
	email_pw_login_credentials.active == 1
`

// Wird verwendet um zu ermitteln ob ein Benutzer bestimmte berechtigungen benötigt um sich anzumelden
var SQLITE_GET_USER_GROUP_DIRECTORY_SERVICE_FILTER_SIGNON = `
SELECT
	CASE WHEN  COUNT(user_directory_service_filter.udsfid) >= 1
		THEN 'YES'
		ELSE 'NO'
	END AS as_login_cred
FROM user_directory_service_filter
WHERE 
	user_directory_service_filter.directory_service_id == ? AND
	user_directory_service_filter.filter == ? ANd
	user_directory_service_filter.active == 1
`

// Wird verwendet um zu ermitteln ob der Aktuelle Benutzer die Entsprechenden berechtigungen hat
var SQLITE_GET_USER_HAS_PERMISSIONS_FOR_FILTER = `
SELECT
	CASE WHEN COUNT(email_pw_login_credentials.lcid) >= 1
		THEN 'GRANTED'
		ELSE 'NOT_GRANTED'
	END AS group_permitted,
	CASE WHEN COUNT(user_permissions.user_id) >= 1
		THEN 'GRANTED'
		ELSE 'NOT_GRANTED'
	END AS user_permitted
FROM email_pw_login_credentials
JOIN users ON users.uid == email_pw_login_credentials.uid AND  users.active == 1
JOIN user_directory_service_members ON user_directory_service_members.user_id == users.uid AND user_directory_service_members.active == 1
LEFT JOIN user_group_member ON user_group_member.uid == email_pw_login_credentials.uid AND  user_group_member.active == 1 AND user_group_member.service_id == user_directory_service_members.directory_service_id
LEFT JOIN user_group_permissions ON user_group_permissions.group_id == user_group_member.gid AND user_group_permissions.active == 1 AND user_group_permissions.directory_service_id == user_directory_service_members.directory_service_id
LEFT JOIN user_permissions ON user_permissions.user_id == email_pw_login_credentials.uid AND user_permissions.active == 1 AND user_permissions.directory_service_id ==  user_directory_service_members.directory_service_id
WHERE
	email_pw_login_credentials.owner_pkey == ? AND
	user_directory_service_members.directory_service_id == ? AND
	(user_group_permissions.name == ? OR user_permissions.permission == ?) AND
	email_pw_login_credentials.active == 1
LIMIT 1
`

// Wird verwendet um zu überprüfen ob ein Schlüssel bereits in der Srtating Login Prozess Tabelle vorhanden ist
var SQLITE_GET_KEY_USED_BY_LOGIN_PROCESS = `
SELECT
	CASE WHEN COUNT(user_session_starting_request.ussr) >= 1
		THEN 'NOT_GRANTED'
		ELSE 'GRANTED'
	END AS user_permitted
FROM user_session_starting_request
WHERE user_session_starting_request.service_id == ? AND user_session_starting_request.one_time_client_session_pkey == ?
`

// Wird verwendet um zu überprüfen ob ein Schlüssel bereits in der Sitzungstabelle verwendet wird
var SQLITE_GET_KEY_USED_BY_LOGIN_SESSION = `
SELECT
	CASE WHEN COUNT(user_sessions.usid) >= 1
		THEN 'NOT_GRANTED'
		ELSE 'GRANTED'
	END AS user_permitted
FROM user_sessions
WHERE user_sessions.service_id == ? AND user_sessions.client_pkey == ?
`

// Wird verwendet um zu überprüfen ob ein Schlüssel bereits in der Schlüsselpaar Tabelle vorhanden ist
var SQLITE_GET_KEY_USED_BY_KEY_PAIR = `
SELECT
	CASE WHEN COUNT(key_pairs.kpid) >= 1
		THEN 'NOT_GRANTED'
		ELSE 'GRANTED'
	END AS user_permitted
FROM key_pairs
WHERE key_pairs.active == 1 AND key_pairs.public_key == ?
`

// Wird verwendet um zu überprüfen ob ein Schlüssel beretis in der Benutzer Tabelle als Masterschlüssel verwendet wird
var SQLITE_GET_KEY_USED_BY_USER_AS_MSATER_KEY = `
SELECT
	CASE WHEN COUNT(users.uid) >= 1
		THEN 'NOT_GRANTED'
		ELSE 'GRANTED'
	END AS user_permitted
FROM users
WHERE users.active == 1 AND users.master_pkey == ?
`
