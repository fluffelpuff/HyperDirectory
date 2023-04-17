package base

import "fmt"

type HDRIntrReqError struct {
	InternalError error
	ExternalError error
}

func (e *HDRIntrReqError) Error() string {
	return fmt.Sprintf("HDRIntrReqError: %s", e.InternalError)
}

func NewHDRIntrReqError(internal_error error, response_error error) *HDRIntrReqError {
	return &HDRIntrReqError{InternalError: internal_error, ExternalError: response_error}
}
