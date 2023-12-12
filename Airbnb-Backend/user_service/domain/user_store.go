package domain

import "go.mongodb.org/mongo-driver/bson/primitive"

type UserStore interface {
	Get(id primitive.ObjectID) (*User, error)
	GetAll() ([]*User, error)
	Register(user *User) (*User, error)
	GetOneUser(username string) (*User, error)
	GetByEmail(email string) (*User, error)
	UpdateUserUsername(user *User) error
	UpdateUser(updateUser *User) (*User, error)
	DeleteAccount(userID primitive.ObjectID) error
}
