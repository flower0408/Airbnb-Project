package handlers

import (
	"encoding/json"
	"github.com/casbin/casbin"
	"github.com/cristalhq/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"user_service/authorization"
	"user_service/casbinAuthorization"
	"user_service/domain"
	"user_service/errors"
	"user_service/service"
)

var (
	jwtKey      = []byte(os.Getenv("SECRET_KEY"))
	verifier, _ = jwt.NewVerifierHS(jwt.HS256, jwtKey)
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

	CasbinMiddleware1, err := casbin.NewEnforcerSafe("./rbac_model.conf", "./policy.csv")

	log.Println("auth service successful init of enforcer")
	if err != nil {
		log.Fatal(err)
	}

	router.Use(ExtractTraceInfoMiddleware)
	router.HandleFunc("/{id}", handler.Get).Methods("GET")
	router.HandleFunc("/", handler.GetAll).Methods("GET")
	router.HandleFunc("/", handler.Register).Methods("POST")
	router.HandleFunc("/getOne/{username}", handler.GetOne).Methods("GET")
	router.HandleFunc("/profile/", handler.Profile).Methods("GET")
	router.HandleFunc("/mailExist/{mail}", handler.MailExist).Methods("GET")
	router.HandleFunc("/changeUsername", handler.ChangeUsername).Methods("POST")
	router.HandleFunc("/{userID}", handler.UpdateUser).Methods("PATCH")

	http.Handle("/", router)
	log.Fatal(http.ListenAndServe(":8002", casbinAuthorization.CasbinMiddleware(CasbinMiddleware1)(router)))
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

func (handler *UserHandler) UpdateUser(writer http.ResponseWriter, req *http.Request) {

	vars := mux.Vars(req)
	userID, err := primitive.ObjectIDFromHex(vars["userID"])
	if err != nil {
		http.Error(writer, "Invalid user ID", http.StatusBadRequest)
		return
	}

	existingUser, err := handler.service.Get(userID)
	if err != nil {
		http.Error(writer, "User not found", http.StatusBadRequest)
		return
	}

	var updatePayload map[string]interface{}
	if err := json.NewDecoder(req.Body).Decode(&updatePayload); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateUserFields(updatePayload); err != nil {
		http.Error(writer, err.Message, http.StatusBadRequest)
		return
	}

	if newEmail, ok := updatePayload["email"].(string); ok && newEmail != existingUser.Email {
		if _, err := handler.service.DoesEmailExist(newEmail); err == nil {
			http.Error(writer, "Updated email already exists", http.StatusMethodNotAllowed)
			return
		}
	}

	for key := range updatePayload {
		switch key {
		case "id", "username", "userType":
			delete(updatePayload, key)
		}
	}

	if err := mapstructure.Decode(updatePayload, &existingUser); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	updatedUser, err := handler.service.UpdateUser(existingUser)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(updatedUser, writer)
}

func validateUserFields(fields bson.M) *ValidationError {
	// Validate Email
	if email, ok := fields["email"].(string); ok {
		emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
		if !emailRegex.MatchString(email) {
			return &ValidationError{Message: "Invalid email format"}
		}
	}

	// Validate Residence
	if residence, ok := fields["residence"].(string); ok {
		residenceRegex := regexp.MustCompile(`^[a-zA-Z0-9\s,'-]{3,35}$`)
		if !residenceRegex.MatchString(residence) {
			return &ValidationError{Message: "Invalid residence format"}
		}
	}

	// Validate Age
	if age, ok := fields["age"].(int); ok {
		if age <= 0 || age >= 100 {
			return &ValidationError{Message: "Age should be a number over 0 and less than 100"}
		}
	}

	// Validate Firstname and Lastname
	if firstname, ok := fields["firstName"].(string); ok {
		nameRegex := regexp.MustCompile(`^[a-zA-Z]{3,20}$`)
		if !nameRegex.MatchString(firstname) {
			return &ValidationError{Message: "Invalid firstname format. It must contain only letters and be 3-20 characters long"}
		}
	}

	if lastname, ok := fields["lastName"].(string); ok {
		nameRegex := regexp.MustCompile(`^[a-zA-Z]{3,20}$`)
		if !nameRegex.MatchString(lastname) {
			return &ValidationError{Message: "Invalid lastname format. It must contain only letters and be 3-20 characters long"}
		}
	}

	// Validate Gender
	if gender, ok := fields["gender"].(string); ok {
		if gender != "Male" && gender != "Female" && gender != "Other" {
			return &ValidationError{Message: "Gender should be either 'Male', 'Female', or 'Other'"}
		}
	}

	return nil
}

func (handler *UserHandler) ChangeUsername(writer http.ResponseWriter, request *http.Request) {
	var username domain.UsernameChange
	err := json.NewDecoder(request.Body).Decode(&username)
	if err != nil {
		log.Println(err)
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	status, statusCode, err := handler.service.ChangeUsername(username)

	if err != nil {
		log.Println("Error in ChangeUsername:", err)
		var errorMessage string

		switch status {
		case "GetUserErr":
			errorMessage = "Error getting user"
		case "baseErr":
			errorMessage = "Internal server error"
		default:
			errorMessage = "An error occurred: " + err.Error()
		}

		http.Error(writer, errorMessage, statusCode)
		return
	}

	writer.WriteHeader(http.StatusOK)
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

func (handler *UserHandler) GetOne(writer http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	username := vars["username"]

	user, err := handler.service.GetOneUser(username)
	if err != nil {
		log.Println(err)
		writer.WriteHeader(http.StatusNotFound)
	}
	jsonResponse(user, writer)
}

func (handler *UserHandler) Profile(writer http.ResponseWriter, req *http.Request) {

	bearer := req.Header.Get("Authorization")
	if bearer == "" {
		log.Println("Authorization header missing")
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bearerToken := strings.Split(bearer, "Bearer ")
	if len(bearerToken) != 2 {
		log.Println("Malformed Authorization header")
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := bearerToken[1]
	log.Printf("Token: %s\n", tokenString)

	token, err := jwt.Parse([]byte(tokenString), verifier)
	if err != nil {
		log.Println("Token parsing error:", err)
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims := authorization.GetMapClaims(token.Bytes())
	log.Printf("Token Claims: %+v\n", claims)
	username := claims["username"]

	user, err := handler.service.GetOneUser(username)
	if err != nil {
		log.Println("GetOneUser error:", err)
		http.Error(writer, "User not found", http.StatusNotFound)
		return
	}
	log.Printf("Retrieved User: %+v\n", user)
	jsonResponse(user, writer)
}

func (handler *UserHandler) MailExist(writer http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	mail, ok := vars["mail"]
	if !ok {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	id, err := handler.service.DoesEmailExist(mail)
	if err != nil {
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	_, err = writer.Write([]byte(id))
	if err != nil {
		log.Println("error in response user service")
		log.Println(err.Error())
		return
	}
}
func ExtractTraceInfoMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
