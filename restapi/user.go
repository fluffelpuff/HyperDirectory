package restapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/fluffelpuff/HyperDirectory/base"
	db "github.com/fluffelpuff/HyperDirectory/database"

	"github.com/gorilla/rpc/v2/json2"
)

type User struct {
	Database *db.Database
}

/*
Überprüft ob die Anmeldeinformationen korrekt sind
*/

func (t *User) VerifyLoginCredentials(r *http.Request, args *base.VerifyLoginCredentialsRequest, result *bool) error {
	// Es wird geprüft ob das Objekt korrekt ist
	if args == nil {
		return fmt.Errorf("VerifyLoginCredentials: ")
	}
	if args.PublicLoginCredentialKey == nil {
		return fmt.Errorf("VerifyLoginCredentials: ")
	}

	// Es wird geprüft ob das Passwort 64 Zeichen lang ist
	if len(*args.PublicLoginCredentialKey) != 66 {
		*result = false
		return nil
	}

	// Die Request Metadaten werden zusammengefasst
	meta_data := base.RequestMetaData{}

	// Es wird geprüft ob es einen Origin Eintrag gibt
	if args.MetaData != nil {
		meta_data = *args.MetaData
	}

	// Es wird eine Anfrage an die Datenbank gestellt
	db_check_result := t.Database.VerifyLoginCredentials(*args.PublicLoginCredentialKey, &meta_data)

	// Die Antwort wird zurückgesendet
	*result = db_check_result

	// Der Vorgang wurde ohne fehler durchgeführt
	return nil
}

/*
Ruft den Account Index ab, dieser wird z.b benötigt um einen Anmeldevorgang auszuführen
*/

func (t *User) GetUserLoginProcessHash(r *http.Request, args *base.VerifyLoginCredentialsRequest, result *string) error {
	// Es wird geprüft ob das Objekt korrekt ist
	if args == nil {
		return fmt.Errorf("GetUserLoginProcessHash: invalid request")
	}
	if args.PublicLoginCredentialKey == nil {
		return fmt.Errorf("GetUserLoginProcessHash: invalid request")
	}

	// Es wird geprüft ob das Passwort 64 Zeichen lang ist
	if len(*args.PublicLoginCredentialKey) != 64 {
		return fmt.Errorf("GetUserLoginProcessHash: invalid password validation hash")
	}

	// Die Request Metadaten werden zusammengefasst
	meta_data := base.RequestMetaData{}

	// Es wird geprüft ob es einen Origin Eintrag gibt
	if args.MetaData != nil {
		meta_data = *args.MetaData
	}

	// Es wird eine Anfrage an die Datenbank gestellt
	db_check_result := t.Database.VerifyLoginCredentials(*args.PublicLoginCredentialKey, &meta_data)
	if !db_check_result {
		return fmt.Errorf("GetUserLoginProcessHash: unkown user data")
	}

	// Der Aktuelle Login Prozesshash wird abgerufen
	login_process_hash, err := t.Database.GetUserLoginProcessKey(*args.PublicLoginCredentialKey, &meta_data)
	if err != nil {
		return fmt.Errorf("GetUserLoginProcessHash: " + err.Error())
	}

	// Die Antwort wird zurückgesendet
	*result = login_process_hash

	// Der Vorgang wurde ohne fehler durchgeführt
	return nil
}

/*
Erzeugt eine neue Benutzersitzung
*/

func (t *User) CreateNewUserSession(r *http.Request, args *base.CreateNewUserSessionRequest, result *base.UserSession) error {
	// Es wird geprüft ob das Objekt korrekt ist
	if args == nil {
		return fmt.Errorf("CreateNewUserSession: invalid request")
	}
	if args.PublicLoginCredentialKey == nil {
		return fmt.Errorf("CreateNewUserSession: invalid request")
	}
	if args.LoginCredentialKeySignature == nil {
		return fmt.Errorf("CreateNewUserSession: invalid request")
	}
	if args.LoginProcessKey == nil {
		return fmt.Errorf("CreateNewUserSession: invalid request")
	}

	// Die Request Metadaten werden zusammengefasst
	meta_data := base.RequestMetaData{}

	// Es wird geprüft ob es einen Origin Eintrag gibt
	if args.MetaData != nil {
		meta_data = *args.MetaData
	}

	// Es wird eine Anfrage an die Datenbank gestellt
	db_check_result := t.Database.VerifyLoginCredentials(*args.PublicLoginCredentialKey, &meta_data)
	if !db_check_result {
		return fmt.Errorf("CreateNewUserSession: unkown user data")
	}

	// Es wird eine neue Sitzung in der Datenbank erstetllt
	user_session, err := t.Database.CreateNewUserSession(*args.PublicLoginCredentialKey, *args.LoginCredentialKeySignature, *args.LoginProcessKey, &meta_data)
	if err != nil {
		return fmt.Errorf("CreateNewUserSession: " + err.Error())
	}

	// Die Antwort wird zurückgesendet
	*result = *user_session

	// Der Vorgang wurde ohne fehler durchgeführt
	return nil
}

/*
Wird verwendet um einen neuen Benutzer zu erstellen
*/

func (t *User) CreateNewEMailBasedNoneUserRoot(r *http.Request, args *base.CreateNewUserNoneRoot, result *base.UserSession) error {
	// Speichert den Namen der Aktuellen Funktion ab
	function_name_var := "@create_new_user_none_root"

	// Die Request Metadaten werden zusammengefasst
	source_meta_data, err := GetMetadataWithDbEnty(t.Database, r, function_name_var)
	if err != nil {
		return &json2.Error{
			Code:    500,
			Message: "Internal error",
		}
	}

	// Die Aktuellen Dienstdaten werden geprüft
	is_acccepted, user_authorized_function, directory_service_user_io, err := ValidateServiceAPIUser(t.Database, r, function_name_var, *source_meta_data)
	if err != nil {
		return &json2.Error{
			Code:    500,
			Message: "Invalid request, aborted",
		}
	}

	// Sollten die API Daten nicht Akzeptiert werden, wird der Vorgang abgebrochen
	if !is_acccepted {
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, unkown user",
		}
	}

	// Sollte der Benutzer nicht berechtigt sein, diese Funktion auszuführen, wird der vorgang abgebrochen
	if !user_authorized_function {
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, not authorized for this function",
		}
	}

	// Es wird geprüft ob das Request Objekt korrekt ist
	if !args.PreValidate() {
		return &json2.Error{
			Code:    401,
			Message: "Bad Request",
		}
	}

	// Es wird geprüft ob die Optionen zulässig sind
	create_session_id, groups := false, []string{}
	for i := range args.Options {
		// Der String wird gesplittet
		splited := strings.Split(args.Options[i], ":")

		// Es wird ermittelt um welchen befehl es sich handelt
		switch splited[0] {
		case "add_group":
			// Es wird geprüft ob mindestens 1 Eintrag auf dem Stack vorhanden ist
			if len(splited) != 2 {
				return &json2.Error{Code: 401, Message: "Bad Request"}
			}

			// Es wird geprüft ob es sich um einen gültigen Gruppennamen handelt
			if !base.IsValidateGroupName(splited[1]) {
				return &json2.Error{Code: 401, Message: "Bad Request"}
			}

			// Die Gruppe wird zwischengespeichert
			groups = append(groups, splited[1])
		case "create_session_id":
			if !create_session_id {
				create_session_id = true
			}
		default:
			return &json2.Error{Code: 401, Message: "Bad Request"}
		}
	}

	// Es wird geprüft ob der Directory Service API User berechtigt ist die Gruppen zu verwenden
	db_group_result, err := t.Database.GetAllMetaUserGroupsByDirectoryApiUser(base.FetchExplicit, directory_service_user_io, []base.PremissionFilter{base.SET_GROUP_MEMBER}, groups...)
	if err != nil {

	}
	fmt.Println(db_group_result)

	// Es wird geprüft ob es bereits einen benutzer mit der E-Mail Adresse, dem Public Masterkey oder dem Public Owner Key gibt
	email_avail, pu_master_avail, owner_avail, err := t.Database.CheckUserDataAvailability(*args.EMailAddress, *args.PublicMasterKey, *args.CredentialsOwnerPublicKey, directory_service_user_io, *source_meta_data, false)
	if err != nil {
		return fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
	}

	// Es wird geprüft ob die E-Mail bereits verwendet wird
	if !email_avail {
		return fmt.Errorf("email_already_used")
	}

	// Sollte eine der anderen Daten bereits verwendet werden, so wird der Vorgang ohne begründung abgebrochen
	if !pu_master_avail || !owner_avail {
		return fmt.Errorf("data_rejected")
	}

	// Das Benutzerkonto wird erstellt
	_, err = t.Database.CreateNewUserNoneRoot(*args.CredentialsOwnerPublicKey, *args.EncryptedMasterKey, *args.PublicMasterKey, *args.EMailAddress, *args.EncryptedUserPassword, *args.Gender, args.FirstName, args.LastName, directory_service_user_io, *source_meta_data)
	if err != nil {
		return fmt.Errorf("CreateNewUserNoneRoot: " + err.Error())
	}

	// Die Optionen werden Aktiviert

	fmt.Println(groups)

	// Die Daten für die Sitzung werden zurückgegeben
	*result = *new(base.UserSession)

	// Der Vorgang wurde ohne fehler durchgeführt
	return nil
}
