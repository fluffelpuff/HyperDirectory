package apiserver

import (
	"fmt"
	"net/http"

	"github.com/fluffelpuff/HyperDirectory/base"
	hdcrypto "github.com/fluffelpuff/HyperDirectory/crypto"
	db "github.com/fluffelpuff/HyperDirectory/database"
	lunasockets "github.com/fluffelpuff/LunaSockets"

	"github.com/gorilla/rpc/v2/json2"
)

/*
Benutzer RPC API
*/
type User struct {
	Database *db.Database
}

/*
Ruft den Account Index ab, dieser wird z.b benötigt um einen Anmeldevorgang auszuführen
*/
func _CreateNewLoginProcessForUser(db *db.Database, directory_service_user_io *base.DirectoryServiceProcess, args *base.VerifyLoginCredentialsRequest, source_meta_data *base.RequestMetaDataSession) (*base.UserLoginProcessStartResponse, *string, *base.HDRIntrReqError) {
	// Es wird geprüft ob es einen Aktiven Benutzer passender zu dem Öffentlichen Schlüssel passt
	db_result, err := db.CreateNewLoginProcessForUser(*args.PublicLoginCredentialKey, *args.OneTimePublicSessionKey, directory_service_user_io, *source_meta_data)
	if err != nil {
		// Es wird ein fehler zurückgegeben
		return nil, nil, base.NewHDRIntrReqError(fmt.Errorf("_CreateNewLoginProcessForUser: 1: "+err.Error()), &json2.Error{Code: 400, Message: "Internal error"})
	}

	// Die zu verschlüsselenden Daten werden vorbereitet
	capsluted_data := base.EncryptedLoginProcessStartCapsule{OneTimePublicKey: db_result.PublicLoginProcessKey}
	bytes_capsle, err := capsluted_data.ToBytes()
	if err != nil {
		// Es wird ein fehler zurückgegeben
		return nil, nil, base.NewHDRIntrReqError(fmt.Errorf("_CreateNewLoginProcessForUser: 2: "+err.Error()), &json2.Error{Code: 400, Message: "Internal error"})
	}

	// Die Daten werden verschlüsselt
	encrypted_str, err := hdcrypto.ECIESSecp256k1PublicKeyEncryptBytes(*args.OneTimePublicSessionKey, bytes_capsle)
	if err != nil {
		return nil, nil, base.NewHDRIntrReqError(fmt.Errorf("_CreateNewLoginProcessForUser: 3: "+err.Error()), &json2.Error{Code: 400, Message: "Internal error"})
	}

	// Die Daten werden für den Rücktransport vorbereitet
	return_value := new(base.UserLoginProcessStartResponse)
	return_value.EncryptedClientData = encrypted_str

	// Der Vorgang wurde ohne fehler durchgeführt
	return return_value, nil, nil
}

func (t *User) CreateNewLoginProcessForUser(r *http.Request, args *base.VerifyLoginCredentialsRequest, result *base.UserLoginProcessStartResponse) error {
	// Speichert den Namen der Aktuellen Funktion ab und erstellt eine Sitzung in der Datenbank
	function_name_var := "@create_new_login_process"

	// Die Request Metadaten werden zusammengefasst, in die Datenbank geschrieben und abgerufen
	source_meta_data, err := CreateNewHTTPSessionRequestEntryAndGet(t.Database, r, function_name_var)
	if err != nil {
		return &json2.Error{
			Code:    500,
			Message: "Internal error",
		}
	}

	// Es wird geprüft ob das Request Objekt korrekt ist
	if !args.PreValidate() {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcessForUser: 4: Bad request"))

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
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcessForUser: 1: "+err.Error()))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    500,
			Message: "Invalid request, aborted",
		}
	}

	// Sollten die API Daten nicht Akzeptiert werden, wird der Vorgang abgebrochen
	if !is_acccepted {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcessForUser: 2: user not authenticated"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, unkown user",
		}
	}

	// Sollte der Benutzer nicht berechtigt sein, diese Funktion auszuführen, wird der vorgang abgebrochen
	if !user_authorized_function {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcessForUser: 3: user not authenticated"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, not authorized for this function",
		}
	}

	// Es wird geprüft ob der Benutzer bekannt ist
	user_found, access_granted_result, err := t.Database.ValidateUserCredentialsPKey(*args.PublicLoginCredentialKey, directory_service_user_io)
	if err != nil {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcessForUser: 4: "+err.Error()))

		// Es wird eine Fehlermeldung zurückgegeben
		return &json2.Error{
			Code:    500,
			Message: "The service could not be authenticated, internal database error",
		}
	}

	// Sollte der Benutzer nicht gefunden werden, wird der Vorgang abgebrochen
	if !user_found {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcessForUser: 5: "+err.Error()))

		// Es wird eine Fehlermeldung zurückgegeben
		return &json2.Error{
			Code:    500,
			Message: "The service could not be authenticated, internal database error",
		}
	}

	// Sollte der Benutzer nicht berechtigt sein, wird der Vorgang abgebrochen
	if !access_granted_result {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("CreateNewLoginProcessForUser: 6: user not authenticated"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, not authorized for this function",
		}
	}

	// Die Anfrage wird fianl durchgeführt
	complete_result, warning, errx := _CreateNewLoginProcessForUser(t.Database, directory_service_user_io, args, source_meta_data)
	if errx != nil {
		// Sollte eine Warnung vorhanden sein, wird diese übergeben
		if warning != nil {
			CloseSessionRequest(t.Database, source_meta_data, warning, errx.InternalError)
			return errx.ExternalError
		} else {
			CloseSessionRequest(t.Database, source_meta_data, nil, errx.InternalError)
			return errx.ExternalError
		}
	}

	// Die Daten werden zurückgegeben
	*result = *complete_result

	// Die Sitzung wird wieder geschlossen
	if warning != nil {
		CloseSessionRequest(t.Database, source_meta_data, warning, nil)
	} else {
		CloseSessionRequest(t.Database, source_meta_data, nil, nil)
	}

	// Der Vorgang wurde ohne Fehler fertigestellt
	return nil
}

/*
Erzeugt eine neue Benutzersitzung
*/
func (t *User) FinalCreateNewUserSessionByLoginProcessKey(r *http.Request, args *base.CreateNewUserSessionRequest, result *base.UserSessionDbResult) error {
	// Speichert den Namen der Aktuellen Funktion ab und erstellt eine Sitzung in der Datenbank
	function_name_var := "@create_new_user_none_root"

	// Die Request Metadaten werden zusammengefasst, in die Datenbank geschrieben und abgerufen
	source_meta_data, err := CreateNewHTTPSessionRequestEntryAndGet(t.Database, r, function_name_var)
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
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("FinalCreateNewUserSessionByLoginProcessKey: 1: "+err.Error()))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    500,
			Message: "Invalid request, aborted",
		}
	}

	// Sollten die API Daten nicht Akzeptiert werden, wird der Vorgang abgebrochen
	if !is_acccepted {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("FinalCreateNewUserSessionByLoginProcessKey: 2: user not authenticated"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, unkown user",
		}
	}

	// Sollte der Benutzer nicht berechtigt sein, diese Funktion auszuführen, wird der vorgang abgebrochen
	if !user_authorized_function {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("FinalCreateNewUserSessionByLoginProcessKey: 3: user not authenticated"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, not authorized for this function",
		}
	}

	// Es wird geprüft ob es eine Wartende Sitzung für den Aktuellen Schlüssel gibt, wenn ja wird der Private Schlüssel und die DatenbankId zurückgegeben
	_, _, found_session, granted, err := t.Database.HasOpenAndWaitingLoginProcessSessionForKey(*args.PublicSessionKey, directory_service_user_io)
	if err != nil {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("FinalCreateNewUserSessionByLoginProcessKey: 4: "+err.Error()))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    500,
			Message: "Internal error",
		}
	}

	// Sollte keine Sitzung vorhanden sein, wird der Vorgang abgebrochen
	if !found_session {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("FinalCreateNewUserSessionByLoginProcessKey: 4: unkown session"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, unkown session",
		}
	}

	// Sollte es bereits eine Sitzung geben, wird der vorgang abgebrochen
	if !granted {
		// Die Sitzung wird wieder geschlossen
		CloseSessionRequest(t.Database, source_meta_data, nil, fmt.Errorf("FinalCreateNewUserSessionByLoginProcessKey: 5: session always finally created"))

		// Es wird ein fehler zurückgegeben
		return &json2.Error{
			Code:    401,
			Message: "The service could not be authenticated, not authorized for this function",
		}
	}

	// Die Daten werden mit dem Privaten Schlüssel aus der Datenbank entschlüsselt

	// Es wird eine neue Sitzung auf Basis des Login Credentials Key, des Server Side Keys sowie des OneTime Session Keys erzeugt

	// Der Vorgang wurde ohne fehler durchgeführt
	return nil
}

/*
Wird verwendet um einen neuen Benutzer zu erstellen
*/
func _CreateNewEMailBasedUserNoneRoot(db *db.Database, directory_service_user_io *base.DirectoryServiceProcess, args *base.CreateNewUserNoneRoot, source_meta_data *base.RequestMetaDataSession) (*base.UserCreateResponse, *string, *base.HDRIntrReqError) {
	// Es wird geprüft ob es bereits einen benutzer mit der E-Mail Adresse, dem Public Masterkey oder dem Public Owner Key gibt
	email_avail, pu_master_avail, owner_avail, err := db.CheckUserDataAvailability(*args.EMailAddress, *args.PublicMasterKey, *args.CredentialsOwnerPublicKey, directory_service_user_io, *source_meta_data)
	if err != nil {
		// Es wird ein fehler zurückgegeben
		return nil, nil, base.NewHDRIntrReqError(fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 7: "+err.Error()), &json2.Error{Code: 400, Message: "Internal error"})
	}

	// Es wird geprüft ob die E-Mail bereits verwendet wird
	if !email_avail {
		// Es wird ein fehler zurückgegeben
		return nil, nil, base.NewHDRIntrReqError(fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 7: email alrady used"), &json2.Error{Code: 400, Message: "email_alrady_used"})
	}

	// Sollte eine der anderen Daten bereits verwendet werden, so wird der Vorgang ohne begründung abgebrochen
	if !pu_master_avail || !owner_avail {
		// Es wird ein fehler zurückgegeben
		return nil, nil, base.NewHDRIntrReqError(fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 8: master or owner key alrady used"), &json2.Error{Code: 400, Message: "data_rejected"})
	}

	// Das Benutzerkonto wird erstellt
	db_result, err := db.CreateNewUserNoneRoot(*args.CredentialsOwnerPublicKey, *args.EncryptedMasterKey, *args.PublicMasterKey, *args.EMailAddress, *args.EncryptedUserPassword, *args.Gender, args.FirstName, args.LastName, directory_service_user_io, *source_meta_data)
	if err != nil {
		// Es wird ein fehler zurückgegeben
		return nil, nil, base.NewHDRIntrReqError(fmt.Errorf("CreateNewEMailBasedUserNoneRoot: 9: "+err.Error()), &json2.Error{Code: 400, Message: "internal error"})
	}

	// Die Antwort wird gebaut
	response_data := new(base.UserCreateResponse)
	response_data.UserDirectoryServiceId = db_result.UserDirectoryId
	response_data.IsRoot = db_result.IsRoot

	// Sofern eine neue Sitzung erstellt werden soll, wird der Vorgang nun durchgeführt
	if args.CreateClientSession != nil {
		if *args.CreateClientSession {
			// Es wird versucht die Sitzung in der Datenbank zu öffnen
			ses, err := db.CreateNewUserSessionByUID(db_result.UserId, directory_service_user_io, *source_meta_data)
			if err != nil {
				// Es wird festgelegt dass keine SessionIds vorhanden sind
				response_data.HasDataForClient = false

				// Der Fehler wird an den Server übermittelt
				response_data.Errors = append(response_data.Errors, err.Error())

				// Die Daten werden zurückgegeben
				response_data.Errors = append(response_data.Errors, "Internal error by creating session")
				warning := "CreateNewEMailBasedUserNoneRoot: 10: " + err.Error()
				return response_data, &warning, nil
			}

			// Die zu verschlüsselenden Daten werden vorbereitet
			capsluted_data := base.EncryptedSessionCapsule{ClientsidePrivKey: ses.ClientsidePrivKey, ClintsidePkey: ses.ClintsidePkey}
			bytes_capsle, err := capsluted_data.ToBytes()
			if err != nil {
				// Es wird festgelegt dass keine SessionIds vorhanden sind
				response_data.HasDataForClient = false

				// Der Fehler wird an den Server übermittelt
				response_data.Errors = append(response_data.Errors, err.Error())

				// Die Daten werden zurückgegeben
				warning := "CreateNewEMailBasedUserNoneRoot: 11: " + err.Error()
				return response_data, &warning, nil
			}

			// Die Daten werden verschlüsselt
			encrypted_str, err := hdcrypto.ECIESSecp256k1PublicKeyEncryptBytes(*args.PublicMasterKey, bytes_capsle)
			if err != nil {
				// Es wird festgelegt dass keine SessionIds vorhanden sind
				response_data.HasDataForClient = false

				// Der Fehler wird an den Server übermittelt
				response_data.Errors = append(response_data.Errors, err.Error())

				// Die Daten werden zurückgegeben
				warning := "CreateNewEMailBasedUserNoneRoot: 12: " + err.Error()
				return response_data, &warning, nil
			}

			// Die Daten werden vorbereitet
			response_data.EncryptedClientData = encrypted_str
			response_data.HasDataForClient = true

			// Der Vorgang wurde ohne fehler durchgeführt
			return response_data, nil, nil
		}
	}

	// Es wird festgelegt dass keine SessionIds vorhanden sind
	response_data.HasDataForClient = false

	// Der Vorgang wurde ohne fehler durchgeführt
	return response_data, nil, nil
}

func (t *User) CreateNewEMailBasedUserNoneRoot(req *lunasockets.Request, args *base.CreateNewUserNoneRoot) (*base.UserCreateResponse, error) {
	// Es wird geprüft ob die RPC Sitzungsdaten vorhanden sind
	if len(req.OutPassedArgs) < 1 {
		return nil, fmt.Errorf("internal error, no live session 1")
	}

	// Es wird gerpüft ob der API User berechtigt ist einen neuen Benutezr zu erstellen, wenn ja wird ein Reqest erstellt
	source_meta_data, err := VDSPAG_DB_ENTRY(t.Database, req, "@create_new_user_none_root")
	if err != nil {
		return nil, &json2.Error{
			Code:    500,
			Message: "Internal error",
		}
	}

	fmt.Println(source_meta_data)

	// DIe Aktielle Sitzung wird geschlossen
	t.Database.CloseEntryRequestProcess(source_meta_data, nil, nil)

	// Die Sitzung wird wieder geschlossen
	return nil, fmt.Errorf("Error")
}
