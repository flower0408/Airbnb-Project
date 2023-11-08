package domain

type AuthStore interface {
	Register(credentials *Credentials) error
	GetOneUser(username string) (*User, error)
}
