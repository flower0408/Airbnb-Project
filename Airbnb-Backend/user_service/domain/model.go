package domain

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID          primitive.ObjectID `bson:"_id" json:"id"`
	Firstname   string             `bson:"firstName,omitempty" json:"firstName,omitempty"`
	Lastname    string             `bson:"lastName,omitempty" json:"lastName,omitempty"`
	Gender      Gender             `bson:"gender,omitempty" json:"gender,omitempty"`
	Age         int                `bson:"age,omitempty" json:"age,omitempty"`
	Residence   string             `bson:"residence,omitempty" json:"residence,omitempty"`
	Email       string             `bson:"email" json:"email"`
	Username    string             `bson:"username" json:"username"`
	UserType    UserType           `bson:"userType" json:"userType"`
	Highlighted bool               `bson:"highlighted" json:"highlighted"`
}

type Gender string

const (
	Male   = "Male"
	Female = "Female"
)

type UserType string

const (
	Guest = "Guest"
	Host  = "Host"
)

type UsernameChange struct {
	OldUsername string `json:"old_username"`
	NewUsername string `json:"new_username"`
}
