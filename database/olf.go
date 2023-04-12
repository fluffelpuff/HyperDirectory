package database

import "github.com/fluffelpuff/HyperDirectory/base"

/*
Gibt an ob die Login Credentials korrekt sind
*/
func (obj *Database) VerifyLoginCredentials(public_login_cred_key string, req_metadata *base.RequestMetaData) bool {
	// Der Lockguard wird gelockt
	obj.lock.Lock()

	// Es wird geprüft ob die Datenbank vorhanden ist

	// Es wird geprüft ob die SQLite Datenbank vorhanden ist
	return true
}

/*
Wird verwendet um eine neue Sitzung zu erstellen
*/
func (obj *Database) CreateNewUserSession(public_login_cred_key string, public_login_cred_sig string, login_process_pkey string, req_metadata *base.RequestMetaData) (*base.UserSessionDbResult, error) {
	return &base.UserSessionDbResult{}, nil
}

/*
Wird verwendet um die Metadaten einer Sitzung abzurufen
*/
func (obj *Database) GetSessionFromDbById(session_id string, req_metadata *base.RequestMetaData) (*base.UserSessionDbResult, error, error) {
	return nil, nil, nil
}

/*
Wird verwendet um die Login Credentials abzurufen
*/
func (obj *Database) GetLoginCredentialsBySessionId(session_id string, req_metadata *base.RequestMetaData, primary_only bool) ([]*base.LoginCredentials, error, error) {
	return nil, nil, nil
}

/*
Wird verwendet um die API Credentials abzurufen
*/
func (obj *Database) GetApiCredentialsBySessionId(session_id string, req_metadata *base.RequestMetaData) ([]*base.ApiCredentials, error, error) {
	return nil, nil, nil
}

/*
Wird verwendet um alle Apps eines Benutzers abzurufen
*/
func (obj *Database) GetAppCredentialsBySessionId(session_id string, req_metadata *base.RequestMetaData) ([]*base.AppCredentials, error, error) {
	return nil, nil, nil
}

// Wird verwendet um die Schlüsselpaare eines Benutzers abzurufen
func (obj *Database) GetKeyPairsBySessionId(session_id string, req_metadata *base.RequestMetaData, primary_only bool) ([]*base.UserKeyPair, error, error) {
	return nil, nil, nil
}

// Wird verwendet um die Gruppen in denen der Benutzer ist anzuzeigen
func (obj *Database) GetUserGroupsBySessionId(session_id string, req_metadata *base.RequestMetaData) ([]*base.UserGroupData, error, error) {
	return nil, nil, nil
}
