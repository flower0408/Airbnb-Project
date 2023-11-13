package domain

import (
	"encoding/json"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
	"regexp"
	"time"
)

type User struct {
	ID        primitive.ObjectID `bson:"_id" json:"id"`
	FirstName string             `bson:"firstName,omitempty" json:"firstName,omitempty"`
	LastName  string             `bson:"lastName,omitempty" json:"lastName,omitempty"`
	Gender    Gender             `bson:"gender,omitempty" json:"gender,omitempty"`
	Age       int                `bson:"age,omitempty" json:"age,omitempty"`
	Residence string             `bson:"residence,omitempty" json:"residence,omitempty"`
	Email     string             `bson:"email" json:"email"`
	Username  string             `bson:"username" json:"username"`
	Password  string             `bson:"password" json:"password"`
	UserType  UserType           `bson:"userType" json:"userType"`
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

type Credentials struct {
	ID       primitive.ObjectID `bson:"_id" json:"id"`
	Username string             `bson:"username" json:"username"`
	Password string             `bson:"password" json:"password"`
	UserType UserType           `bson:"userType" json:"userType"`
	Verified bool               `bson:"verified" json:"verified"`
}

type Claims struct {
	UserID    primitive.ObjectID `json:"user_id"`
	Username  string             `json:"username"`
	Role      UserType           `json:"userType"`
	ExpiresAt time.Time          `json:"expires_at"`
}

type RegisterValidation struct {
	UserToken string `json:"user_token"`
	MailToken string `json:"mail_token"`
}

type ResendVerificationRequest struct {
	UserToken string `json:"user_token"`
	UserMail  string `json:"user_mail"`
}

func (user *User) ValidateUser() error {
	validate := validator.New()

	err := validate.RegisterValidation("onlyChar", onlyCharactersField)
	if err != nil {
		return err
	}

	err = validate.RegisterValidation("onlyCharAndNum", onlyCharactersAndNumbersField)
	if err != nil {
		return err
	}

	return validate.Struct(user)
}

// Allows only letters [a-z]
func onlyCharactersField(fl validator.FieldLevel) bool {
	re := regexp.MustCompile("[-_a-zA-Z]*")
	matches := re.FindAllString(fl.Field().String(), -1)

	if len(matches) != 1 {
		return false
	}

	return true
}

// Allows only letters [a-z] and numbers [0-9]
func onlyCharactersAndNumbersField(fl validator.FieldLevel) bool {
	re := regexp.MustCompile("[-_a-zA-Z0-9]*")
	matches := re.FindAllString(fl.Field().String(), -1)

	if len(matches) != 1 {
		return false
	}

	return true
}

func (user *User) FromJSON(reader io.Reader) error {
	d := json.NewDecoder(reader)
	return d.Decode(user)
}
