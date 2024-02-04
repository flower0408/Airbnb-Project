package domain

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type Notification struct {
	ID          primitive.ObjectID `bson:"_id" json:"id"`
	ByGuestId   string             `bson:"byGuestId,omitempty" json:"byGuestId"`
	ForHostId   string             `bson:"forHostId,omitempty" json:"forHostId"`
	Description string             `bson:"description,omitempty" json:"description"`
	CreatedAt   time.Time          `bson:"createdAt,omitempty" json:"createdAt"`
}
