package lib

import (
	"fmt"
)

type UserNotFoundError struct {
	Username  string
	UserId    int
	UserToken string
}

func (e UserNotFoundError) Error() string {
	return fmt.Sprintf("user %s %s %snot found", e.Username, e.UserId, e.UserToken)
}
