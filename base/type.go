package base

type PremissionFilter string
type GetDataMode string

type RequestMetaData struct {
	ContentType   string
	ContentLength string
	Connection    string
	Accept        string
	Encodings     string
	UserAgent     string
	SourceIp      string
	Domain        string
	SourcePort    string
}

type RequestMetaDataSession struct {
	DbEntryId int64
}

type PersonalData struct {
}

type LoginCredentials struct {
}

type ApiCredentials struct {
}

type AppCredentials struct {
}

type UserKeyPair struct {
}

type UserGroupData struct {
}

type UserSessionDbResult struct {
	SessionDbId       int64
	ClintsidePkey     string
	ClientsidePrivKey string
}

type VerifyLoginCredentialsRequest struct {
	LoginCredentialSignatureKey *string
	PublicLoginCredentialKey    *string
	OneTimePublicSessionKey     *string
	MetaData                    *RequestMetaData
}

type CreateNewUserSessionRequest struct {
	PublicLoginCredentialKey    *string
	LoginCredentialKeySignature *string
	LoginProcessKey             *string
	MetaData                    *RequestMetaData
}

type NewUserDbResult struct {
	UserDirectoryId string
	UserId          int64
	IsRoot          bool
}

type UserGroupDirectoryApiUser struct {
	SetGroupMembershipPremission bool
	DirectoryServiceId           int64
	UserId                       int64
	Name                         string
	Id                           int64
}

type UserCreateResponse struct {
	IsRoot                 bool
	Errors                 []string
	HasDataForClient       bool
	EncryptedClientData    string
	UserDirectoryServiceId string
}

type LoginProcessKeyCreationDbResult struct {
	PrivateLoginProcessClientKey string
}

type UserLoginProcessStartResponse struct {
	EncryptedClientData string
}
