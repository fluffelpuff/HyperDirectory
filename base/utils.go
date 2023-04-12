package base

import (
	"net/mail"
	"strings"

	"github.com/google/uuid"
)

func ValidateEMail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func PrepareText(p string) string {
	tr := strings.TrimSpace(p)
	low := strings.ToLower(tr)
	return low
}

func ValidateGender(gp string) bool {
	return true
}

func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

func IsValidateHumanName(u string) bool {
	return true
}

func IsValidateGroupName(u string) bool {
	return true
}
