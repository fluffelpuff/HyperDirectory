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
	SessionDbId          int64
	ClintsidePkey        string
	ClientsidePrivKey    string
	ServiceSideSessionId string
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
	UserGroups []string
	UserId     int64
	IsRoot     bool
}

type UserGroupDirectoryApiUser struct {
	SetGroupMembershipPremission bool
	DirectoryServiceId           int64
	UserId                       int64
	Name                         string
	Id                           int64
}

type UserCreateResponse struct {
	IsRoot                  bool
	UserGroups              []string
	Errors                  []string
	EncryptedClientData     string
	ServiceSideSessionId    string
	HasClientSideSession    bool
	HasServiceSideSessionId bool
}

type EncryptedSessionCapsule struct {
	ClientsidePrivKey string `cbor:"1,keyasint,omitempty"`
	ClintsidePkey     string `cbor:"2,keyasint,omitempty"`
}

type LoginProcessKeyCreationDbResult struct {
}
