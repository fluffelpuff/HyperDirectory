package restapi

import (
	"fmt"
	"net/http"

	"github.com/fluffelpuff/HyperDirectory/base"
	hdcrypto "github.com/fluffelpuff/HyperDirectory/crypto"
	db "github.com/fluffelpuff/HyperDirectory/database"

	"github.com/gorilla/rpc/v2/json2"
)

type User struct {
	Database *db.Database
}

/*
Ruft den Account Index ab, dieser wird z.b benötigt um einen Anmeldevorgang auszuführen
*/

func (t *User) CreateNewLoginProcess(r *http.Request, args *base.VerifyLoginCredentialsRequest, result *base.UserLoginProcessStartResponse) error {
	// Speichert den Namen der Aktuellen Funktion ab und erstellt eine Sitzung in der Datenbank
	function_name_var := "@create_new_login_process"

	// Die Request Metadaten werden zusammengefasst, in die Datenbank geschrieben und abgerufen
	source_meta_data, err := CreateNewSessionRequestEntryAndGet(t.Database, r, function_name_var)
	if err != nil {
		return &json2.Error{
			Code:    500,
			Message: "Internal error",
		}
	}

	// Es wird geprüft ob das Request Objekt korrekt ist
	if !args.PreValidate() {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcess: 4: Bad request"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    400,
			Message: "Bad Request",
		}
	}

	// Die Aktuellen Dienstdaten werden geprüft
	is_acccepted, user_authorized_function, directory_service_user_io, err := ValidateServiceAPIUser(t.Database, r, function_name_var, *source_meta_data)
	if err != nil {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcess: 1: "+err.Error()))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    500,
			Message: "Invalid request, aborted",
		}
	}

	// Sollten die API Daten nicht Akzeptiert werden, wird der Vorgang abgebrochen
	if !is_acccepted {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcess: 2: user not authenticated"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, unkown user",
		}
	}

	// Sollte der Benutzer nicht berechtigt sein, diese Funktion auszuführen, wird der vorgang abgebrochen
	if !user_authorized_function {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcess: 3: user not authenticated"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, not authorized for this function",
		}
	}

	// Es wird geprüft ob der Benutzer bekannt ist
	user_found, access_granted_result, err := t.Database.ValidateUserCredentialsPKeyAndStartLoginProcess(*args.PublicLoginCredentialKey, directory_service_user_io)
	if err != nil {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcess: 4: "+err.Error()))

		// Es wird eine Fehlermeldung zurückgegeben
		return &json2.Error{
			Code:    500,
			Message: "The service could not be authenticated, internal database error",
		}
	}

	// Sollte der Benutzer nicht gefunden werden, wird der Vorgang abgebrochen
	if !user_found {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcess: 5: "+err.Error()))

		// Es wird eine Fehlermeldung zurückgegeben
		return &json2.Error{
			Code:    500,
			Message: "The service could not be authenticated, internal database error",
		}
	}

	// Sollte der Benutzer nicht berechtigt sein, wird der Vorgang abgebrochen
	if !access_granted_result {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcess: 6: user not authenticated"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, not authorized for this function",
		}
	}

	// Es wird geprüft ob es einen Aktiven Benutzer passender zu dem Öffentlichen Schlüssel passt
	db_result, err := t.Database.CreateNewLoginProcessKey(*args.PublicLoginCredentialKey, *args.OneTimePublicSessionKey, directory_service_user_io, *source_meta_data)
	if err != nil {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcess: 7: "+err.Error()))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{Code: 400, Message: "Internal error"}
	}

	// Die zu verschlüsselenden Daten werden vorbereitet
	capsluted_data := base.EncryptedLoginProcessStartCapsule{OneTimePublicKey: db_result.PublicLoginProcessKey}
	bytes_capsle, err := capsluted_data.ToBytes()
	if err != nil {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcess: 8: "+err.Error()))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{Code: 400, Message: "Internal error"}
	}

	// Die Daten werden verschlüsselt
	encrypted_str, err := hdcrypto.ECIESSecp256k1PublicKeyEncryptBytes(*args.OneTimePublicSessionKey, bytes_capsle)
	if err != nil {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcess: 9: "+err.Error()))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{Code: 400, Message: "Internal error"}
	}

	// Die Daten werden für den Rücktransport vorbereitet
	return_value := new(base.UserLoginProcessStartResponse)
	return_value.EncryptedClientData = encrypted_str

	// Die Daten werden zurückgesendet
	*result = *return_value

	// Der Vorgang wurde ohne fehler durchgeführt
	return nil
}

/*
Erzeugt eine neue Benutzersitzung
*/

func (t *User) FinalCreateNewUserSessionByLoginProcessKey(r *http.Request, args *base.CreateNewUserSessionRequest, result *base.UserSessionDbResult) error {
	// Speichert den Namen der Aktuellen Funktion ab und erstellt eine Sitzung in der Datenbank
	function_name_var := "@create_new_user_none_root"

	// Die Request Metadaten werden zusammengefasst, in die Datenbank geschrieben und abgerufen
	source_meta_data, err := CreateNewSessionRequestEntryAndGet(t.Database, r, function_name_var)
	if err != nil {
		return &json2.Error{
			Code:    500,
			Message: "Internal error",
		}
	}

	// Die Aktuellen Dienstdaten werden geprüft
	is_acccepted, user_authorized_function, directory_service_user_io, err := ValidateServiceAPIUser(t.Database, r, function_name_var, *source_meta_data)
	if err != nil {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("FinalCreateNewUserSessionByLoginProcessKey: 1: "+err.Error()))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    500,
			Message: "Invalid request, aborted",
		}
	}

	// Sollten die API Daten nicht Akzeptiert werden, wird der Vorgang abgebrochen
	if !is_acccepted {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("FinalCreateNewUserSessionByLoginProcessKey: 2: user not authenticated"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, unkown user",
		}
	}

	// Sollte der Benutzer nicht berechtigt sein, diese Funktion auszuführen, wird der vorgang abgebrochen
	if !user_authorized_function {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("FinalCreateNewUserSessionByLoginProcessKey: 3: user not authenticated"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, not authorized for this function",
		}
	}

	// Es wird geprüft ob es eine Wartende Sitzung für den Aktuellen Schlüssel gibt, wenn ja wird der Private Schlüssel und die DatenbankId zurückgegeben

	// Die Daten werden mit dem Privaten Schlüssel aus der Datenbank entschlüsselt

	// Es wird eine neue Sitzung auf Basis des Login Credentials Key, des Server Side Keys sowie des OneTime Session Keys erzeugt

	// Der Vorgang wurde ohne fehler durchgeführt
	return nil
}

/*
Wird verwendet um einen neuen Benutzer zu erstellen
*/

func (t *User) CreateNewEMailBasedUserNoneRoot(r *http.Request, args *base.CreateNewUserNoneRoot, result *base.UserCreateResponse) error {
	// Speichert den Namen der Aktuellen Funktion ab und erstellt eine Sitzung in der Datenbank
	function_name_var := "@create_new_user_none_root"

	// Die Request Metadaten werden zusammengefasst, in die Datenbank geschrieben und abgerufen
	source_meta_data, err := CreateNewSessionRequestEntryAndGet(t.Database, r, function_name_var)
	if err != nil {
		return &json2.Error{
			Code:    500,
			Message: "Internal error",
		}
	}

	// Es wird geprüft ob das Request Objekt korrekt ist
	if !args.PreValidate() {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 4: Bad request"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    400,
			Message: "Bad Request",
		}
	}

	// Die Aktuellen Dienstdaten werden geprüft
	is_acccepted, user_authorized_function, directory_service_user_io, err := ValidateServiceAPIUser(t.Database, r, function_name_var, *source_meta_data)
	if err != nil {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 1: "+err.Error()))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    500,
			Message: "Invalid request, aborted",
		}
	}

	// Sollten die API Daten nicht Akzeptiert werden, wird der Vorgang abgebrochen
	if !is_acccepted {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 2: user not authenticated"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, unkown user",
		}
	}

	// Sollte der Benutzer nicht berechtigt sein, diese Funktion auszuführen, wird der vorgang abgebrochen
	if !user_authorized_function {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 3: user not authenticated"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, not authorized for this function",
		}
	}

	// Es wird geprüft ob es bereits einen benutzer mit der E-Mail Adresse, dem Public Masterkey oder dem Public Owner Key gibt
	email_avail, pu_master_avail, owner_avail, err := t.Database.CheckUserDataAvailability(*args.EMailAddress, *args.PublicMasterKey, *args.CredentialsOwnerPublicKey, directory_service_user_io, *source_meta_data)
	if err != nil {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 7: "+err.Error()))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{Code: 400, Message: "Internal error"}
	}

	// Es wird geprüft ob die E-Mail bereits verwendet wird
	if !email_avail {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 7: email alrady used"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{Code: 400, Message: "email_alrady_used"}
	}

	// Sollte eine der anderen Daten bereits verwendet werden, so wird der Vorgang ohne begründung abgebrochen
	if !pu_master_avail || !owner_avail {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 8: master or owner key alrady used"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{Code: 400, Message: "data_rejected"}
	}

	// Das Benutzerkonto wird erstellt
	db_result, err := t.Database.CreateNewUserNoneRoot(*args.CredentialsOwnerPublicKey, *args.EncryptedMasterKey, *args.PublicMasterKey, *args.EMailAddress, *args.EncryptedUserPassword, *args.Gender, args.FirstName, args.LastName, directory_service_user_io, *source_meta_data)
	if err != nil {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 9: "+err.Error()))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{Code: 400, Message: "internal error"}
	}

	// Die Antwort wird gebaut
	response_data := new(base.UserCreateResponse)
	response_data.UserDirectoryServiceId = db_result.UserDirectoryId
	response_data.IsRoot = db_result.IsRoot

	// Sofern eine neue Sitzung erstellt werden soll, wird der Vorgang nun durchgeführt
	if *args.CreateClientSession {
		// Es wird versucht die Sitzung in der Datenbank zu öffnen
		ses, err := t.Database.CreateNewUserSessionByUID(db_result.UserId, directory_service_user_io, *source_meta_data)
		if err != nil {
			// Es wird festgelegt dass keine SessionIds vorhanden sind
			response_data.HasDataForClient = false

			// Der Fehler wird an den Server übermittelt
			response_data.Errors = append(response_data.Errors, err.Error())

			// Die Sitzung wird wieder geschlossen
			warning := fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 10: " + err.Error()).Error()
			CloseSessionRequest(t.Database, r, source_meta_data, &warning, nil)

			// Die Daten werden zurückgegeben
			response_data.Errors = append(response_data.Errors, "Internal error by creating session")
			*result = *response_data
			return nil
		}

		// Die zu verschlüsselenden Daten werden vorbereitet
		capsluted_data := base.EncryptedSessionCapsule{ClientsidePrivKey: ses.ClientsidePrivKey, ClintsidePkey: ses.ClintsidePkey}
		bytes_capsle, err := capsluted_data.ToBytes()
		if err != nil {
			// Es wird festgelegt dass keine SessionIds vorhanden sind
			response_data.HasDataForClient = false

			// Der Fehler wird an den Server übermittelt
			response_data.Errors = append(response_data.Errors, err.Error())

			// Die Sitzung wird wieder geschlossen
			warning := fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 11: " + err.Error()).Error()
			CloseSessionRequest(t.Database, r, source_meta_data, &warning, nil)

			// Die Daten werden zurückgegeben
			*result = *response_data
			return nil
		}

		// Die Daten werden verschlüsselt
		encrypted_str, err := hdcrypto.ECIESSecp256k1PublicKeyEncryptBytes(*args.PublicMasterKey, bytes_capsle)
		if err != nil {
			// Es wird festgelegt dass keine SessionIds vorhanden sind
			response_data.HasDataForClient = false

			// Der Fehler wird an den Server übermittelt
			response_data.Errors = append(response_data.Errors, err.Error())

			// Die Sitzung wird wieder geschlossen
			warning := fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 12: " + err.Error()).Error()
			CloseSessionRequest(t.Database, r, source_meta_data, &warning, nil)

			// Die Daten werden zurückgegeben
			*result = *response_data
			return nil
		}

		// Die Daten werden vorbereitet
		response_data.EncryptedClientData = encrypted_str
		response_data.HasDataForClient = true

		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, r, source_meta_data, nil, nil)

		// Die Daten für die Sitzung werden zurückgegeben
		*result = *response_data

		// Der Vorgang wurde ohne fehler durchgeführt
		return nil
	}

	// Es wird festgelegt dass keine SessionIds vorhanden sind
	response_data.HasDataForClient = false

	// Die Sitzung wird wieder geschlossen
	CloseSessionRequest(t.Database, r, source_meta_data, nil, nil)

	// Die Daten für die Sitzung werden zurückgegeben
	*result = *response_data

	// Der Vorgang wurde ohne fehler durchgeführt
	return nil
}
