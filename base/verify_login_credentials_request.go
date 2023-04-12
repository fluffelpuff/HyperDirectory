package base

type VerifyLoginCredentialsRequest struct {
	LoginCredentialSignatureKey *string
	PublicLoginCredentialKey    *string
	OneTimePublicSessionKey     *string
	MetaData                    *RequestMetaData
}

func (obj *VerifyLoginCredentialsRequest) PreValidate() bool {
	// Es wird geprüft ob die benötigten Datenfelder vorhanden sind
	return true
}
