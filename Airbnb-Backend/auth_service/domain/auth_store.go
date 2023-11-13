package domain

import "go.mongodb.org/mongo-driver/bson/primitive"

type AuthStore interface {
	Register(credentials *Credentials) error
	GetOneUser(username string) (*Credentials, error)
	GetAll() ([]*Credentials, error)
	GetOneUserByID(id primitive.ObjectID) *Credentials
	UpdateUser(user *Credentials) error
}
