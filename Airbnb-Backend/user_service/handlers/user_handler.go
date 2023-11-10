package handlers

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
	"net/http"
	"regexp"
	"user_service/domain"
	"user_service/errors"
	"user_service/service"
)

type UserHandler struct {
	service *application.UserService
}

func NewUserHandler(service *application.UserService) *UserHandler {
	return &UserHandler{
		service: service,
	}
}

func (handler *UserHandler) Init(router *mux.Router) {
	router.HandleFunc("/{id}", handler.Get).Methods("GET")
	router.HandleFunc("/", handler.GetAll).Methods("GET")
	router.HandleFunc("/", handler.Register).Methods("POST")
	http.Handle("/", router)
}

type ValidationError struct {
	Message string `json:"message"`
}

func validateUser(user *domain.User) *ValidationError {
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	residenceRegex := regexp.MustCompile(`^[a-zA-Z0-9\s,'-]{3,35}$`)

	// Validate Email
	if user.Email == "" {
		return &ValidationError{Message: "Email cannot be empty"}
	}
	if !emailRegex.MatchString(user.Email) {
		return &ValidationError{Message: "Invalid email format"}
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
	if user.Firstname == "" {
		return &ValidationError{Message: "FirstName cannot be empty"}
	}
	nameRegex := regexp.MustCompile(`^[a-zA-Z]{3,20}$`)
	if !nameRegex.MatchString(user.Firstname) {
		return &ValidationError{Message: "Invalid firstname format. It must contain only letters and be 3-20 characters long"}
	}
	if user.Lastname == "" {
		return &ValidationError{Message: "LastName cannot be empty"}
	}
	if !nameRegex.MatchString(user.Lastname) {
		return &ValidationError{Message: "Invalid lastname format. It must contain only letters and be 3-20 characters long"}
	}

	// Validate UserType
	if user.UserType == "" {
		return &ValidationError{Message: "UserType cannot be empty"}
	}
	if user.UserType != "Guest" && user.UserType != "Host" {
		return &ValidationError{Message: "UserType should be either 'Guest' or 'Host'"}
	}

	return nil
}

func (handler *UserHandler) Register(writer http.ResponseWriter, req *http.Request) {
	var user domain.User
	err := json.NewDecoder(req.Body).Decode(&user)
	if err != nil {
		log.Println(err)
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateUser(&user); err != nil {
		http.Error(writer, err.Message, http.StatusBadRequest)
		return
	}

	saved, err := handler.service.Register(&user)
	if err != nil {
		if err.Error() == errors.DatabaseError {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		} else {
			http.Error(writer, err.Error(), http.StatusBadRequest)
		}
		return
	}
	newUser, err := json.Marshal(saved)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(200)
	jsonResponse(newUser, writer)

}

func (handler *UserHandler) GetAll(writer http.ResponseWriter, req *http.Request) {
	users, err := handler.service.GetAll()
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	jsonResponse(users, writer)
}

func (handler *UserHandler) Get(writer http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id, ok := vars["id"]
	if !ok {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := handler.service.Get(objectID)
	if err != nil {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	jsonResponse(user, writer)
}
