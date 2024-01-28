package domain

import (
	"context"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserStore interface {
	Get(ctx context.Context, id primitive.ObjectID) (*User, error)
	GetAll(ctx context.Context) ([]*User, error)
	Register(ctx context.Context, user *User) (*User, error)
	GetOneUser(ctx context.Context, username string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	UpdateUserUsername(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, updateUser *User) (*User, error)
	DeleteAccount(ctx context.Context, userID primitive.ObjectID) error
	IsHighlighted(ctx context.Context, host string, authToken string) (bool, error)
}
