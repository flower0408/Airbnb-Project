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
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
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
	jwtKey                 = []byte(os.Getenv("SECRET_KEY"))
	verifier, _            = jwt.NewVerifierHS(jwt.HS256, jwtKey)
	reservationServiceHost = os.Getenv("RESERVATIONS_SERVICE_HOST")
	reservationServicePort = os.Getenv("RESERVATIONS_SERVICE_PORT")
)

type UserHandler struct {
	service *application.UserService
	tracer  trace.Tracer
}

func NewUserHandler(service *application.UserService, tracer trace.Tracer) *UserHandler {
	return &UserHandler{
		service: service,
		tracer:  tracer,
	}
}

func (handler *UserHandler) Init(router *mux.Router) {

	CasbinMiddleware1, err := casbin.NewEnforcerSafe("./rbac_model.conf", "./policy.csv")

	log.Println("user service successful init of enforcer")
	if err != nil {
		log.Fatal(err)
	}

	router.Use(ExtractTraceInfoMiddleware)
	router.HandleFunc("/{id}", handler.Get).Methods("GET")
	router.HandleFunc("/", handler.GetAll).Methods("GET")
	router.HandleFunc("/", handler.Register).Methods("POST")
	router.HandleFunc("/getOne/{username}", handler.GetOne).Methods("GET")
	router.HandleFunc("/getId/{username}", handler.GetId).Methods("GET")
	router.HandleFunc("/profile/", handler.Profile).Methods("GET")
	router.HandleFunc("/mailExist/{mail}", handler.MailExist).Methods("GET")
	router.HandleFunc("/changeUsername", handler.ChangeUsername).Methods("POST")
	router.HandleFunc("/{userID}", handler.UpdateUser).Methods("PATCH")
	router.HandleFunc("/{id}/delete", handler.DeleteAccount).Methods("DELETE")

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
	ctx, span := handler.tracer.Start(req.Context(), "UserHandler.Register")
	defer span.End()

	var user domain.User
	err := json.NewDecoder(req.Body).Decode(&user)
	if err != nil {
		log.Println(err)
		span.SetStatus(codes.Error, err.Error())
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateUser(&user); err != nil {
		http.Error(writer, err.Message, http.StatusBadRequest)
		return
	}

	saved, err := handler.service.Register(ctx, &user)
	if err != nil {
		if err.Error() == errors.DatabaseError {
			span.SetStatus(codes.Error, err.Error())
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		} else {
			span.SetStatus(codes.Error, err.Error())
			http.Error(writer, err.Error(), http.StatusBadRequest)
		}
		return
	}
	newUser, err := json.Marshal(saved)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(200)
	jsonResponse(newUser, writer)

}

func (handler *UserHandler) UpdateUser(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "UserHandler.UpdateUser")
	defer span.End()

	vars := mux.Vars(req)
	userID, err := primitive.ObjectIDFromHex(vars["userID"])
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(writer, "Invalid user ID", http.StatusBadRequest)
		return
	}

	existingUser, err := handler.service.Get(ctx, userID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(writer, "User not found", http.StatusBadRequest)
		return
	}

	var updatePayload map[string]interface{}
	if err := json.NewDecoder(req.Body).Decode(&updatePayload); err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateUserFields(updatePayload); err != nil {
		http.Error(writer, err.Message, http.StatusBadRequest)
		return
	}

	if newEmail, ok := updatePayload["email"].(string); ok && newEmail != existingUser.Email {
		if _, err := handler.service.DoesEmailExist(ctx, newEmail); err == nil {
			//span.SetStatus(codes.Error, err.Error())
			http.Error(writer, "Updated email already exists", http.StatusMethodNotAllowed)
			span.SetStatus(codes.Error, "Updated email already exists")
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
		span.SetStatus(codes.Error, err.Error())
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	updatedUser, err := handler.service.UpdateUser(ctx, existingUser)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
	ctx, span := handler.tracer.Start(request.Context(), "UserHandler.ChangeUsername")
	defer span.End()

	var username domain.UsernameChange
	err := json.NewDecoder(request.Body).Decode(&username)
	if err != nil {
		log.Println(err)
		span.SetStatus(codes.Error, err.Error())
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	status, statusCode, err := handler.service.ChangeUsername(ctx, username)

	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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

		span.SetStatus(codes.Error, err.Error())
		http.Error(writer, errorMessage, statusCode)
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *UserHandler) GetAll(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "UserHandler.GetAll")
	defer span.End()

	users, err := handler.service.GetAll(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	jsonResponse(users, writer)
}

func (handler *UserHandler) Get(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "UserHandler.Get")
	defer span.End()

	vars := mux.Vars(req)
	id, ok := vars["id"]
	if !ok {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := handler.service.Get(ctx, objectID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	jsonResponse(user, writer)
}

func (handler *UserHandler) GetOne(writer http.ResponseWriter, request *http.Request) {
	ctx, span := handler.tracer.Start(request.Context(), "UserHandler.GetOne")
	defer span.End()

	vars := mux.Vars(request)
	username := vars["username"]

	user, err := handler.service.GetOneUser(ctx, username)
	if err != nil {
		log.Println(err)
		span.SetStatus(codes.Error, err.Error())
		writer.WriteHeader(http.StatusNotFound)
	}
	jsonResponse(user, writer)
}

func (handler *UserHandler) GetId(writer http.ResponseWriter, request *http.Request) {
	ctx, span := handler.tracer.Start(request.Context(), "UserHandler.GetId")
	defer span.End()

	vars := mux.Vars(request)
	username := vars["username"]

	userId, err := handler.service.GetOneUserId(ctx, username)
	if err != nil {
		log.Println(err)
		span.SetStatus(codes.Error, err.Error())
		writer.WriteHeader(http.StatusNotFound)
	}
	jsonResponse(userId, writer)
}

func (handler *UserHandler) DeleteAccount(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "UserHandler.DeleteAccount")
	defer span.End()

	vars := mux.Vars(req)
	userID, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(writer, "Invalid user ID", http.StatusBadRequest)
		return
	}
	err = handler.service.DeleteAccount(ctx, userID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(writer, "Error deleting account", http.StatusInternalServerError)
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func extractBearerToken(authHeader string) string {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

func (handler *UserHandler) Profile(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "UserHandler.Profile")
	defer span.End()

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
		span.SetStatus(codes.Error, err.Error())
		log.Println("Token parsing error:", err)
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims := authorization.GetMapClaims(token.Bytes())
	log.Printf("Token Claims: %+v\n", claims)
	username := claims["username"]

	user, err := handler.service.GetOneUser(ctx, username)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		log.Println("GetOneUser error:", err)
		http.Error(writer, "User not found", http.StatusNotFound)
		return
	}
	log.Printf("Retrieved User: %+v\n", user)
	jsonResponse(user, writer)
}

func (handler *UserHandler) MailExist(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "UserHandler.MailExist")
	defer span.End()

	vars := mux.Vars(req)
	mail, ok := vars["mail"]
	if !ok {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	id, err := handler.service.DoesEmailExist(ctx, mail)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	_, err = writer.Write([]byte(id))
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
