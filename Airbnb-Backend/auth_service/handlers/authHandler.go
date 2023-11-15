package handlers

import (
	"auth_service/domain"
	"auth_service/errors"
	"auth_service/service"
	"auth_service/store"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
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

	loginRouter := router.Methods(http.MethodPost).Subrouter()
	loginRouter.HandleFunc("/login", handler.Login)

	registerRouter := router.Methods(http.MethodPost).Subrouter()
	registerRouter.HandleFunc("/register", handler.Register)
	registerRouter.Use(MiddlewareUserValidation)

	verifyRouter := router.Methods(http.MethodPost).Subrouter()
	verifyRouter.HandleFunc("/verifyAccount", handler.VerifyAccount)

	router.HandleFunc("/", handler.GetAll).Methods("GET")
	router.HandleFunc("/login", handler.Login).Methods("POST")
	router.HandleFunc("/register", handler.Register).Methods("POST")
	router.HandleFunc("/verifyAccount", handler.VerifyAccount).Methods("POST")
	router.HandleFunc("/resendVerify", handler.ResendVerificationToken).Methods("POST")
	router.HandleFunc("/recoverPasswordToken", handler.SendRecoveryPasswordToken).Methods("POST")
	router.HandleFunc("/checkRecoverToken", handler.CheckRecoveryPasswordToken).Methods("POST")
	router.HandleFunc("/recoverPassword", handler.RecoverPassword).Methods("POST")
	http.Handle("/", router)
}

func (handler *AuthHandler) GetAll(writer http.ResponseWriter, req *http.Request) {
	users, err := handler.service.GetAll()
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	jsonResponse(users, writer)
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

	myUser := req.Context().Value(domain.User{}).(domain.User)

	if err := validateUser(&myUser); err != nil {
		http.Error(writer, err.Message, http.StatusBadRequest)
		return
	}

	token, statusCode, err := handler.service.Register(&myUser)
	if statusCode == 55 {
		writer.WriteHeader(http.StatusFound)
		http.Error(writer, err.Error(), 302)
		return
	}
	if err != nil {
		http.Error(writer, err.Error(), statusCode)
		return
	}

	jsonResponse(token, writer)
}

func (handler *AuthHandler) VerifyAccount(writer http.ResponseWriter, req *http.Request) {

	var request domain.RegisterValidation
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		log.Println(err)
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	if len(request.UserToken) == 0 {
		http.Error(writer, errors.InvalidUserTokenError, http.StatusBadRequest)
		return
	}

	err = handler.service.VerifyAccount(&request)
	if err != nil {
		if err.Error() == errors.InvalidTokenError {
			log.Println(err.Error())
			http.Error(writer, errors.InvalidTokenError, http.StatusNotAcceptable)
		} else if err.Error() == errors.ExpiredTokenError {
			log.Println(err.Error())
			http.Error(writer, errors.ExpiredTokenError, http.StatusNotFound)
		}
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *AuthHandler) ResendVerificationToken(writer http.ResponseWriter, req *http.Request) {

	var request domain.ResendVerificationRequest
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		http.Error(writer, errors.InvalidRequestFormatError, http.StatusBadRequest)
		log.Fatal(err.Error())
		return
	}

	err = handler.service.ResendVerificationToken(&request)
	if err != nil {
		if err.Error() == errors.InvalidResendMailError {
			http.Error(writer, err.Error(), http.StatusNotAcceptable)
			return
		} else {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *AuthHandler) SendRecoveryPasswordToken(writer http.ResponseWriter, req *http.Request) {

	buf := new(strings.Builder)
	_, err := io.Copy(buf, req.Body)
	if err != nil {
		http.Error(writer, errors.InvalidRequestFormatError, http.StatusBadRequest)
		log.Fatal(err.Error())
		return
	}

	id, statusCode, err := handler.service.SendRecoveryPasswordToken(buf.String())
	if err != nil {
		http.Error(writer, err.Error(), statusCode)
		return
	}

	jsonResponse(id, writer)
}

func (handler *AuthHandler) CheckRecoveryPasswordToken(writer http.ResponseWriter, req *http.Request) {

	var request domain.RegisterValidation
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		http.Error(writer, errors.InvalidRequestFormatError, http.StatusBadRequest)
		log.Fatal(err.Error())
		return
	}

	err = handler.service.CheckRecoveryPasswordToken(&request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusNotAcceptable)
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *AuthHandler) RecoverPassword(writer http.ResponseWriter, req *http.Request) {
	var request domain.RecoverPasswordRequest
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		http.Error(writer, errors.InvalidRequestFormatError, http.StatusBadRequest)
		log.Fatal(err.Error())
		return
	}

	err = handler.service.RecoverPassword(&request)
	if err != nil {
		if err.Error() == errors.NotMatchingPasswordsError {
			http.Error(writer, err.Error(), http.StatusNotAcceptable)
			return
		}
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *AuthHandler) Login(writer http.ResponseWriter, req *http.Request) {
	var request domain.Credentials
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := handler.service.Login(&request)
	if err != nil {
		if err.Error() == errors.NotVerificatedUser {
			http.Error(writer, token, http.StatusLocked)
			return
		}
		http.Error(writer, "Username not exist!", http.StatusBadRequest)
		return
	}

	if token == "not_same" {
		http.Error(writer, "Wrong password", http.StatusUnauthorized)
		return
	}

	writer.Write([]byte(token))
}

func MiddlewareUserValidation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		user := &domain.User{}
		err := user.FromJSON(request.Body)
		if err != nil {
			http.Error(responseWriter, "Unable to Decode JSON", http.StatusBadRequest)
			return
		}

		err = user.ValidateUser()
		if err != nil {
			http.Error(responseWriter, fmt.Sprintf("Validation Error:\n %s.", err), http.StatusBadRequest)
			return
		}

		ctx := context.WithValue(request.Context(), domain.User{}, *user)
		request = request.WithContext(ctx)

		next.ServeHTTP(responseWriter, request)
	})
}
