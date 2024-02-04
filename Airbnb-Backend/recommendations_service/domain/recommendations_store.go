package domain

import (
	"context"
)

type RecommendationStore interface {
	CreateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id *string) error
	UpdateUserUsername(ctx context.Context, user *User) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByIdUsername(ctx context.Context, id string) (*User, error)
	CreateAccommodation(ctx context.Context, accommodation *Accommodation) error
	DeleteAccommodation(ctx context.Context, id *string) error
	CreateRate(ctx context.Context, rate *Rate) error
	DeleteRate(ctx context.Context, id *string) error
	UpdateRate(ctx context.Context, rate *Rate) (*Rate, error)
	CreateReservation(ctx context.Context, reservation *Reservation) error
	GetRecommendAccommodationsId(ctx context.Context, id string) ([]string, error)
}
