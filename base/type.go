package base

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

type RequestMetaDataDbEntry struct {
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

type UserSession struct {
	UserMode                string
	SessionId               string
	LoginProcessHash        string
	SessionBrowserPublicKey string
	SessionServerPublicKey  string
	SessionServerSignature  string
}

type VerifyLoginCredentialsRequest struct {
	PublicLoginCredentialKey *string
	MetaData                 *RequestMetaData
}

type CreateNewUserSessionRequest struct {
	PublicLoginCredentialKey    *string
	LoginCredentialKeySignature *string
	LoginProcessKey             *string
	MetaData                    *RequestMetaData
}

type NewUserDbResult struct {
	UserId int64
	IsRoot bool
}

type PremissionFilter string
type GetDataMode string
