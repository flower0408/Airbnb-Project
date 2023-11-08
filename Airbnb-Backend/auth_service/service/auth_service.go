package application

import (
	"auth_service/domain"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"
	"unicode"
)

var (
	userServiceHost = os.Getenv("USER_SERVICE_HOST")
	userServicePort = os.Getenv("USER_SERVICE_PORT")
)

var jwtKey = []byte("my_secret_key")

type AuthService struct {
	store domain.AuthStore
}

func NewAuthService(store domain.AuthStore) *AuthService {
	return &AuthService{
		store: store,
	}
}

type ValidationError struct {
	Message string `json:"message"`
}

func (v *ValidationError) Error() string {
	return v.Message
}

func verifyPassword(s string) (valid bool) {
	hasUpperCase := false
	hasLowerCase := false
	hasDigit := false
	hasSpecial := false

	for _, c := range s {
		switch {
		case unicode.IsNumber(c):
			hasDigit = true
		case unicode.IsUpper(c):
			hasUpperCase = true
		case unicode.IsLower(c):
			hasLowerCase = true
		case unicode.Is(unicode.S, c) || unicode.IsPunct(c):
			hasSpecial = true
		}
	}

	valid = len(s) >= 11 && hasUpperCase && hasLowerCase && hasDigit && hasSpecial
	return
}

func validateUser(user *domain.User) *ValidationError {
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	nameRegex := regexp.MustCompile(`^[a-zA-Z]{3,20}$`)
	residenceRegex := regexp.MustCompile(`^[a-zA-Z\s,'-]*$`)
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]{4,20}$`)

	// Validate Email
	if !emailRegex.MatchString(user.Email) {
		return &ValidationError{Message: "Invalid email format"}
	}

	// Validate FirstName and LastName
	if !nameRegex.MatchString(user.FirstName) {
		return &ValidationError{Message: "Invalid firstname format. It must contain only letters and be 3-20 characters long"}
	}
	if !nameRegex.MatchString(user.LastName) {
		return &ValidationError{Message: "Invalid lastname format. It must contain only letters and be 3-20 characters long"}
	}

	// Validate Residence
	if !residenceRegex.MatchString(user.Residence) {
		return &ValidationError{Message: "Invalid residence format"}
	}

	// Validate Age
	if user.Age <= 0 || user.Age >= 100 {
		return &ValidationError{Message: "Age should be a number over 0 and less than 100"}
	}

	if !verifyPassword(user.Password) {
		return &ValidationError{Message: "Invalid password format. It should be at least 11 characters, with at least one uppercase letter, one lowercase letter, one digit, and one special character"}
	}

	// Validate Username
	if !usernameRegex.MatchString(user.Username) {
		return &ValidationError{Message: "Invalid username format. It must be 4-20 characters long and contain only letters, numbers, underscores, and hyphens"}
	}

	// Validate UserType
	if user.UserType != "Guest" && user.UserType != "Host" {
		return &ValidationError{Message: "UserType should be either 'Guest' or 'Host'"}
	}

	return nil
}

func (service *AuthService) Register(user *domain.User) error {

	if err := validateUser(user); err != nil {
		return err
	}

	existingUser, err := service.store.GetOneUser(user.Username)
	if err != nil {
		return err
	}

	if existingUser != nil {
		return errors.New("Username already exists")
	}

	pass := []byte(user.Password)
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hash)

	body, err := json.Marshal(user)
	if err != nil {
		return err
	}

	userServiceEndpoint := fmt.Sprintf("http://%s:%s/", userServiceHost, userServicePort)

	userServiceRequest, _ := http.NewRequest("POST", userServiceEndpoint, bytes.NewReader(body))
	responseUser, err := http.DefaultClient.Do(userServiceRequest)
	if err != nil {
		return err
	}

	response, err := io.ReadAll(responseUser.Body)
	if err != nil {
		return err
	}

	var newUser domain.User
	json.Unmarshal(response, &newUser)

	credentials := domain.Credentials{
		ID:       newUser.ID,
		Username: user.Username,
		Password: user.Password,
		UserType: user.UserType,
	}

	return service.store.Register(&credentials)
}

func (service *AuthService) Login(credentials *domain.Credentials) (string, error) {
	user, err := service.store.GetOneUser(credentials.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("Invalid username or password")
		}
		return "", fmt.Errorf("Error retrieving user: %v", err)
	}

	if user == nil {
		return "", errors.New("Invalid username or password")
	}

	passError := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if passError != nil {
		return "", errors.New("Invalid username or password")
	}
	expirationTime := time.Now().Add(15 * time.Minute)

	claims := &domain.Claims{
		Username: user.Username,
		Role:     user.UserType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", errors.New("Error generating token")
	}

	return tokenString, nil
}
