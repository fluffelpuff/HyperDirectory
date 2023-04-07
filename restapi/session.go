package restapi

import (
	"time"

	db "github.com/fluffelpuff/HyperDirectory/database"
)

type Session struct {
	Database *db.Database
}

/*
Ruft eine Sitzung aus der Datenbank ab
*/

func (t *Session) GetSessionFromDbById(args *EmptyArgs, reply *int64) error {
	*reply = time.Now().Unix()
	return nil
}

/*
Ruft die Persönlichendaten ab
*/

func (t *Session) GetPersonalDataBySessionId(args *EmptyArgs, reply *int64) error {
	*reply = time.Now().Unix()
	return nil
}

/*
Ruft alle verfügbaren Anmeldeinformationen ab
*/

func (t *Session) GetLoginCredentialsBySessionId(args *EmptyArgs, reply *int64) error {
	*reply = time.Now().Unix()
	return nil
}

/*
Ruft all API Credentials ab
*/

func (t *Session) GetApiCredentialsBySessionId(args *EmptyArgs, reply *int64) error {
	*reply = time.Now().Unix()
	return nil
}

/*
Ruft all App Credentials
*/

func (t *Session) GetAppCredentialsBySessionId(args *EmptyArgs, reply *int64) error {
	*reply = time.Now().Unix()
	return nil
}

/*
Ruft all Arbeitgeberinformationen ab
*/

func (t *Session) GetEmployerBySessionId(args *EmptyArgs, reply *int64) error {
	*reply = time.Now().Unix()
	return nil
}

/*
Ruft alle Addressdaten ab
*/

func (t *Session) GetPersonalAddressesBySessionId(args *EmptyArgs, reply *int64) error {
	*reply = time.Now().Unix()
	return nil
}

/*
Ruft alle Bankdaten ab
*/

func (t *Session) GetBankDetailsBySessionId(args *EmptyArgs, reply *int64) error {
	*reply = time.Now().Unix()
	return nil
}

/*
Ruft alle Schlüsselpaare ab
*/

func (t *Session) GetKeyPairsBySessionId(args *EmptyArgs, reply *int64) error {
	*reply = time.Now().Unix()
	return nil
}

/*
Ruft alle Benutzergruppen ab
*/

func (t *Session) GetUserGroupsBySessionId(args *EmptyArgs, reply *int64) error {
	*reply = time.Now().Unix()
	return nil
}

/*
Gibt an, ob der Benutezr mitglied einer bestimmten Gruppe ist
*/

func (t *Session) UserIsMemberOfGroup(args *EmptyArgs, reply *int64) error {
	*reply = time.Now().Unix()
	return nil
}
