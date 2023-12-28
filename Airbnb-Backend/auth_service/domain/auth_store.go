package domain

import (
	"context"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AuthStore interface {
	Register(ctx context.Context, credentials *Credentials) error
	GetOneUser(ctx context.Context, username string) (*Credentials, error)
	GetAll(ctx context.Context) ([]*Credentials, error)
	GetOneUserByID(ctx context.Context, id primitive.ObjectID) *Credentials
	UpdateUser(ctx context.Context, user *Credentials) error
	UpdateUserUsername(ctx context.Context, user *Credentials) error
	DeleteUser(ctx context.Context, username string) error
}
