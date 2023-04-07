package restapi

type EmptyArgs struct{}

type LoginDataRequest struct {
	Username     string
	PasswordHash string
}
