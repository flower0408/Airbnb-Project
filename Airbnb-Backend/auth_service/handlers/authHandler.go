package handlers

import (
	"auth_service/domain"
	"auth_service/service"
	"auth_service/store"
	"encoding/json"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"regexp"
	"unicode"
)

type AuthHandler struct {
	service *application.AuthService
	store   *store.AuthMongoDBStore
}

func NewAuthHandler(service *application.AuthService) *AuthHandler {
	return &AuthHandler{
		service: service,
	}
}

func (handler *AuthHandler) Init(router *mux.Router) {
	router.HandleFunc("/login", handler.Login).Methods("POST")
	router.HandleFunc("/register", handler.Register).Methods("POST")
	http.Handle("/", router)
}

type ValidationError struct {
	Message string `json:"message"`
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
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]{4,30}$`)
	residenceRegex := regexp.MustCompile(`^[a-zA-Z0-9\s,'-]{3,35}$`)

	// Validate Email
	if user.Email == "" {
		return &ValidationError{Message: "Email cannot be empty"}
	}
	if !emailRegex.MatchString(user.Email) {
		return &ValidationError{Message: "Invalid email format"}
	}

	// Validate Username
	if user.Username == "" {
		return &ValidationError{Message: "Username cannot be empty"}
	}
	if !usernameRegex.MatchString(user.Username) {
		return &ValidationError{Message: "Invalid username format. It must be 4-30 characters long and contain only letters, numbers, underscores, and hyphens"}
	}

	// Validate Residence
	if user.Residence == "" {
		return &ValidationError{Message: "Residence cannot be empty"}
	}
	if !residenceRegex.MatchString(user.Residence) {
		return &ValidationError{Message: "Invalid residence format"}
	}

	// Validate Age
	if user.Age <= 0 || user.Age >= 100 {
		return &ValidationError{Message: "Age should be a number over 0 and less than 100"}
	}

	// Validate Firstname and Lastname
	if user.FirstName == "" {
		return &ValidationError{Message: "FirstName cannot be empty"}
	}
	nameRegex := regexp.MustCompile(`^[a-zA-Z]{3,20}$`)
	if !nameRegex.MatchString(user.FirstName) {
		return &ValidationError{Message: "Invalid firstname format. It must contain only letters and be 3-20 characters long"}
	}
	if user.LastName == "" {
		return &ValidationError{Message: "LastName cannot be empty"}
	}
	if !nameRegex.MatchString(user.LastName) {
		return &ValidationError{Message: "Invalid lastname format. It must contain only letters and be 3-20 characters long"}
	}

	// Validate UserType
	if user.UserType == "" {
		return &ValidationError{Message: "UserType cannot be empty"}
	}
	if user.UserType != "Guest" && user.UserType != "Host" {
		return &ValidationError{Message: "UserType should be either 'Guest' or 'Host'"}
	}

	// Validate Password
	if user.Password == "" {
		return &ValidationError{Message: "Password cannot be empty"}
	}
	if !verifyPassword(user.Password) {
		return &ValidationError{Message: "Invalid password format. It should be at least 11 characters, with at least one uppercase letter, one lowercase letter, one digit, and one special character"}
	}

	return nil
}

func (handler *AuthHandler) Register(writer http.ResponseWriter, req *http.Request) {

	var request domain.User
	err := json.NewDecoder(req.Body).Decode(&request)

	if err != nil {
		log.Println(err)
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateUser(&request); err != nil {
		http.Error(writer, err.Message, http.StatusBadRequest)
		return
	}

	code, err := handler.service.Register(&request)
	if err != nil {
		http.Error(writer, err.Error(), code)
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *AuthHandler) Login(writer http.ResponseWriter, req *http.Request) {

	var request domain.Credentials
	err := json.NewDecoder(req.Body).Decode(&request)

	if err != nil {
		log.Println(err)
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := handler.service.Login(&request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusNotFound)
		return
	}
	writer.Write([]byte(token))
}
