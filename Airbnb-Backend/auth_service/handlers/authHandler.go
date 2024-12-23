package handlers

import (
	"auth_service/authorization"
	"auth_service/casbinAuthorization"
	"auth_service/domain"
	"auth_service/errors"
	"auth_service/service"
	"auth_service/store"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/casbin/casbin"
	"github.com/gorilla/mux"
	"github.com/sony/gobreaker"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const EmailServiceUnavailableStatusCode = 55

type AuthHandler struct {
	service *application.AuthService
	store   *store.AuthMongoDBStore
	cb      *gobreaker.CircuitBreaker
	tracer  trace.Tracer
}

var (
	reservationServiceHost   = os.Getenv("RESERVATIONS_SERVICE_HOST")
	reservationServicePort   = os.Getenv("RESERVATIONS_SERVICE_PORT")
	userServiceHost          = os.Getenv("USER_SERVICE_HOST")
	userServicePort          = os.Getenv("USER_SERVICE_PORT")
	accommodationServiceHost = os.Getenv("ACCOMMODATIONS_SERVICE_HOST")
	accommodationServicePort = os.Getenv("ACCOMMODATIONS_SERVICE_PORT")
)

func NewAuthHandler(service *application.AuthService, tracer trace.Tracer) *AuthHandler {
	return &AuthHandler{
		service: service,
		cb:      CircuitBreaker("accommodationService"),
		tracer:  tracer,
	}
}

func (handler *AuthHandler) Init(router *mux.Router) {

	CasbinMiddleware1, err := casbin.NewEnforcerSafe("./rbac_model.conf", "./policy.csv")

	log.Println("auth service successful init of enforcer")
	if err != nil {
		log.Fatal(err)
	}

	router.Use(ExtractTraceInfoMiddleware)
	loginRouter := router.Methods(http.MethodPost).Subrouter()
	loginRouter.HandleFunc("/login", handler.Login)

	registerRouter := router.Methods(http.MethodPost).Subrouter()
	registerRouter.HandleFunc("/register", handler.Register)
	registerRouter.Use(MiddlewareUserValidation)

	verifyRouter := router.Methods(http.MethodPost).Subrouter()
	verifyRouter.HandleFunc("/verifyAccount", handler.AccountConfirmation)

	verifyRecaptchaRouter := router.Methods(http.MethodPost).Subrouter()
	verifyRecaptchaRouter.HandleFunc("/verify-recaptcha", handler.VerifyRecaptcha)

	router.HandleFunc("/", handler.GetAll).Methods("GET")
	router.HandleFunc("/login", handler.Login).Methods("POST")
	router.HandleFunc("/register", handler.Register).Methods("POST")
	router.HandleFunc("/verify-recaptcha", handler.VerifyRecaptcha).Methods("POST")
	router.HandleFunc("/accountConfirmation", handler.AccountConfirmation).Methods("POST")
	router.HandleFunc("/resendVerify", handler.ResendVerificationToken).Methods("POST")
	router.HandleFunc("/recoverPasswordToken", handler.SendRecoveryPasswordToken).Methods("POST")
	router.HandleFunc("/checkRecoverToken", handler.CheckRecoveryPasswordToken).Methods("POST")
	router.HandleFunc("/recoverPassword", handler.RecoverPassword).Methods("POST")
	router.HandleFunc("/changePassword", handler.ChangePassword).Methods("POST")
	router.HandleFunc("/changeUsername", handler.ChangeUsername).Methods("POST")
	router.HandleFunc("/logout", handler.logoutHandler).Methods("POST")
	router.HandleFunc("/deleteUser", handler.DeleteUser).Methods("DELETE")

	http.Handle("/", router)
	log.Fatal(http.ListenAndServeTLS(":8003", "auth_service-cert.pem", "auth_service-key.pem", casbinAuthorization.CasbinMiddleware(CasbinMiddleware1)(router)))
}

func (handler *AuthHandler) logoutHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := extractTokenFromHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No token found"))
		return
	}

	cookie := &http.Cookie{
		Name:     "jwt",
		Value:    tokenString,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, cookie)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logout successful"))
}

func extractTokenFromHeader(request *http.Request) (string, error) {
	authHeader := request.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("No Authorization header found")
	}

	// Check if the header starts with "Bearer "
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("Invalid Authorization header format")
	}

	// Extract the token
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	return tokenString, nil
}
func (handler *AuthHandler) GetAll(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "AuthHandler.GetAll")
	defer span.End()

	users, err := handler.service.GetAll(ctx)
	if err != nil {
		span.SetStatus(codes.Error, "Internal server error")
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

	valid = len(s) >= 11 && len(s) <= 30 && hasUpperCase && hasLowerCase && hasDigit && hasSpecial
	return
}

func validateUser(user *domain.User) *ValidationError {
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{3,35}`)
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]{4,30}$`)
	residenceRegex := regexp.MustCompile(`^[a-zA-Z\s,'-]{3,35}$`)
	nameRegex := regexp.MustCompile(`^[a-zA-Z]{3,20}$`)
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
	if user.Age <= 0 || user.Age > 100 {
		return &ValidationError{Message: "Age should be a number over 0 and less than 100"}
	}

	// Validate Firstname and Lastname
	if user.FirstName == "" {
		return &ValidationError{Message: "FirstName cannot be empty"}
	}

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

func (handler *AuthHandler) VerifyRecaptcha(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "AuthHandler.VerifyRecaptcha")
	defer span.End()

	var recaptchaToken struct {
		Token string `json:"token"`
	}

	err := json.NewDecoder(req.Body).Decode(&recaptchaToken)
	if err != nil {
		log.Println(err)
		span.SetStatus(codes.Error, "Status bad request")
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	// Pozivamo funkciju za proveru reCAPTCHA tokena iz servisa
	isCaptchaValid, err := handler.service.VerifyRecaptcha(ctx, recaptchaToken.Token)
	if err != nil {
		span.SetStatus(codes.Error, "Internal server error")
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	// Vraćamo rezultat provere kao JSON odgovor
	response := struct {
		Success bool `json:"success"`
	}{
		Success: isCaptchaValid,
	}

	json.NewEncoder(writer).Encode(response)
}

func (handler *AuthHandler) Register(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "AuthHandler.Register")
	defer span.End()

	myUser := req.Context().Value(domain.User{}).(domain.User)

	if err := validateUser(&myUser); err != nil {
		span.SetStatus(codes.Error, "Status bad request")
		http.Error(writer, err.Message, http.StatusBadRequest)
		return
	}

	token, statusCode, err := handler.service.Register(ctx, &myUser)
	if statusCode == EmailServiceUnavailableStatusCode {
		writer.WriteHeader(http.StatusFound)
		span.SetStatus(codes.Error, "Email service unavailable")
		http.Error(writer, err.Error(), http.StatusFound)
		return
	}
	if err != nil {
		switch err.Error() {
		case "EmailServiceError":
			http.Error(writer, "Email service is currently unavailable. Please try again later.", http.StatusServiceUnavailable)
			span.SetStatus(codes.Error, "Email service is currently unavailable")
		case "UserServiceError":
			http.Error(writer, "User service is currently unavailable. Please try again later.", http.StatusServiceUnavailable)
			span.SetStatus(codes.Error, "Email service is currently unavailable")
		default:
			span.SetStatus(codes.Error, "Error")
			http.Error(writer, err.Error(), statusCode)
		}
		return
	}

	jsonResponse(token, writer)
}

func (handler *AuthHandler) AccountConfirmation(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "AuthHandler.VerifyAccount")
	defer span.End()

	var request domain.RegisterValidation
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		log.Println(err)
		span.SetStatus(codes.Error, "Status bad request")
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	if len(request.UserToken) == 0 {
		http.Error(writer, errors.InvalidUserTokenError, http.StatusBadRequest)
		return
	}

	err = handler.service.AccountConfirmation(ctx, &request)
	if err != nil {
		if err.Error() == errors.InvalidTokenError {
			log.Println(err.Error())
			span.SetStatus(codes.Error, "Invalid token error")
			http.Error(writer, errors.InvalidTokenError, http.StatusNotAcceptable)
		} else if err.Error() == errors.ExpiredTokenError {
			log.Println(err.Error())
			span.SetStatus(codes.Error, "Expired token error")
			http.Error(writer, errors.ExpiredTokenError, http.StatusNotFound)
		}
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *AuthHandler) ResendVerificationToken(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "AuthHandler.ResendVerificationToken")
	defer span.End()

	var request domain.ResendVerificationRequest
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		span.SetStatus(codes.Error, "Invalid request format error")
		http.Error(writer, errors.InvalidRequestFormatError, http.StatusBadRequest)
		log.Fatal(err.Error())
		return
	}

	err = handler.service.ResendVerificationToken(ctx, &request)
	if err != nil {
		if err.Error() == errors.InvalidResendMailError {
			span.SetStatus(codes.Error, "Invalid resend mail error")
			http.Error(writer, err.Error(), http.StatusNotAcceptable)
			return
		} else {
			span.SetStatus(codes.Error, "Internal server error")
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *AuthHandler) SendRecoveryPasswordToken(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "AuthHandler.SendRecoveryPasswordToken")
	defer span.End()

	buf := new(strings.Builder)
	_, err := io.Copy(buf, req.Body)
	if err != nil {
		span.SetStatus(codes.Error, "Invalid request format error")
		http.Error(writer, errors.InvalidRequestFormatError, http.StatusBadRequest)
		log.Fatal(err.Error())
		return
	}

	id, statusCode, err := handler.service.SendRecoveryPasswordToken(ctx, buf.String())
	if err != nil {
		switch err.Error() {
		case "EmailServiceError":
			http.Error(writer, "Email service is currently unavailable. Please try again later.", http.StatusServiceUnavailable)
			span.SetStatus(codes.Error, "Email service is currently unavailable")
		case "UserServiceError":
			http.Error(writer, "User service is currently unavailable. Please try again later.", http.StatusServiceUnavailable)
			span.SetStatus(codes.Error, "Email service is currently unavailable")
		default:
			http.Error(writer, err.Error(), statusCode)
			span.SetStatus(codes.Error, "Error")
		}
		return
	}

	jsonResponse(id, writer)
}

func (handler *AuthHandler) CheckRecoveryPasswordToken(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "AuthHandler.CheckRecoveryPasswordToken")
	defer span.End()

	var request domain.RegisterValidation
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		span.SetStatus(codes.Error, "Invalid request format error")
		http.Error(writer, errors.InvalidRequestFormatError, http.StatusBadRequest)
		log.Fatal(err.Error())
		return
	}

	err = handler.service.CheckRecoveryPasswordToken(ctx, &request)
	if err != nil {
		span.SetStatus(codes.Error, "Status not acceptable")
		http.Error(writer, err.Error(), http.StatusNotAcceptable)
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *AuthHandler) RecoverPassword(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "AuthHandler.RecoverPassword")
	defer span.End()

	var request domain.RecoverPasswordRequest
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		span.SetStatus(codes.Error, "Invalid request format error")
		http.Error(writer, errors.InvalidRequestFormatError, http.StatusBadRequest)
		log.Fatal(err.Error())
		return
	}

	status, statusCode, err := handler.service.RecoverPassword(ctx, &request)
	if err != nil {
		var errorMessage string

		switch status {
		case "newPassErr":
			errorMessage = "Wrong new password"
		case "baseErr":
			errorMessage = "Internal server error"
		default:
			errorMessage = "An error occurred"
		}

		span.SetStatus(codes.Error, "Error")
		http.Error(writer, errorMessage, statusCode)
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *AuthHandler) ChangePassword(writer http.ResponseWriter, request *http.Request) {
	ctx, span := handler.tracer.Start(request.Context(), "AuthHandler.ChangePassword")
	defer span.End()

	var token string = request.Header.Get("Authorization")
	bearerToken := strings.Split(token, "Bearer ")
	tokenString := bearerToken[1]

	fmt.Println(request.Body)

	var password domain.PasswordChange
	err := json.NewDecoder(request.Body).Decode(&password)
	if err != nil {
		log.Println(err)
		span.SetStatus(codes.Error, "Status bad request")
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	status, statusCode, err := handler.service.ChangePassword(ctx, password, tokenString)

	if err != nil {
		var errorMessage string

		switch status {
		case "oldPassErr":
			errorMessage = "Wrong old password"
		case "newPassErr":
			errorMessage = "Wrong new password"
		case "baseErr":
			errorMessage = "Internal server error"
		default:
			errorMessage = "An error occurred"
		}

		span.SetStatus(codes.Error, "Error")
		http.Error(writer, errorMessage, statusCode)
		return
	}

	writer.WriteHeader(http.StatusOK)

}

func (handler *AuthHandler) ChangeUsername(writer http.ResponseWriter, request *http.Request) {
	ctx, span := handler.tracer.Start(request.Context(), "AuthHandler.ChangeUsername")
	defer span.End()

	var token string = request.Header.Get("Authorization")
	bearerToken := strings.Split(token, "Bearer ")
	tokenString := bearerToken[1]

	fmt.Println(request.Body)

	var username domain.UsernameChange
	err := json.NewDecoder(request.Body).Decode(&username)
	if err != nil {
		log.Println(err)
		span.SetStatus(codes.Error, "Status bad request")
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	status, statusCode, err := handler.service.ChangeUsername(ctx, username, tokenString)

	if err != nil {
		var errorMessage string

		switch status {
		case "oldUsername":
			errorMessage = "Wrong old username"
		case "newUsername":
			errorMessage = "Wrong new username"
		case "baseErr":
			errorMessage = "Internal server error"
		case "UserServiceError":
			errorMessage = "User service is currently unavailable. Please try again later."
		default:
			errorMessage = "An error occurred"
		}

		span.SetStatus(codes.Error, "Error")
		http.Error(writer, errorMessage, statusCode)
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *AuthHandler) Login(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "AuthHandler.Login")
	defer span.End()

	var request domain.Credentials
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		span.SetStatus(codes.Error, "Status bad request")
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := handler.service.Login(ctx, &request)
	if err != nil {
		if err.Error() == errors.NotVerificatedUser {
			http.Error(writer, token, http.StatusLocked)
			span.SetStatus(codes.Error, "Not verification user")
			return
		}
		span.SetStatus(codes.Error, "Username not exist!")
		http.Error(writer, "Username not exist!", http.StatusBadRequest)
		return
	}

	if token == "not_same" {
		span.SetStatus(codes.Error, "Wrong password")
		http.Error(writer, "Wrong password", http.StatusUnauthorized)
		return
	}

	writer.Write([]byte(token))
}

func (handler *AuthHandler) DeleteUser(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "AuthHandler.DeleteUser")
	defer span.End()

	tokenString, err := extractTokenFromHeader(req)
	if err != nil {
		span.SetStatus(codes.Error, "No token found")
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("No token found"))
		return
	}

	username, err := handler.service.ExtractUsernameFromToken(tokenString)
	if err != nil {
		fmt.Println("Error extracting username:", err)
		span.SetStatus(codes.Error, "Error parsing token")
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Error parsing token"))
		return
	}

	var userID string
	var userIDErr error

	// Circuit breaker for getting user ID by username
	_, breakerErr := handler.cb.Execute(func() (interface{}, error) {
		userID, userIDErr = handler.getUserIDByUsername(ctx, username, tokenString)
		return nil, userIDErr
	})

	if breakerErr != nil {
		log.Println("Circuit breaker open:", breakerErr)
		span.SetStatus(codes.Error, "Service Unavailable")
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	if userIDErr != nil {
		fmt.Println("Error getting userId by username:", userIDErr)
		span.SetStatus(codes.Error, "Error getting user ID")
		http.Error(writer, "Error getting user ID", http.StatusInternalServerError)
		return
	}

	parsedToken := authorization.GetToken(tokenString)
	claims := authorization.GetMapClaims(parsedToken.Bytes())
	userType := claims["userType"]

	var hasReservations bool
	var ok bool

	if userType == "Host" {
		// Circuit breaker for checking host reservations
		hasReservationsResult, breakerErr := handler.cb.Execute(func() (interface{}, error) {
			return handler.hasHostReservations(ctx, userID, tokenString)
		})

		if breakerErr != nil {
			log.Println("Circuit breaker open:", breakerErr)
			span.SetStatus(codes.Error, "Service Unavailable")
			http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		hasReservations, ok = hasReservationsResult.(bool)
		if !ok {
			log.Println("Internal server error: Unexpected result type")
			span.SetStatus(codes.Error, "Internal server error")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			return
		}

		if hasReservations {
			http.Error(writer, "Host has reservations, cannot delete account", http.StatusForbidden)
			span.SetStatus(codes.Error, "Host has reservations, cannot delete account")
			return
		} else {
			// Circuit breaker for deleting accommodations
			deleteAccommodationsResult, breakerErr := handler.cb.Execute(func() (interface{}, error) {
				deleteAccommodationsEndpoint := fmt.Sprintf("https://%s:%s/delete_accommodations/%s", accommodationServiceHost, accommodationServicePort, userID)
				/*deleteAccommodationsRequest, err := http.NewRequest("DELETE", deleteAccommodationsEndpoint, nil)
				otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(deleteAccommodationsRequest.Header))
				deleteAccommodationsRequest.Header.Set("Authorization", "Bearer "+tokenString)
				if err != nil {
					span.SetStatus(codes.Error, "Error creating deleteAccommodationsRequest")
					log.Println("Error creating deleteAccommodationsRequest:", err)
					return nil, err
				}*/

				deleteAccommodationsResponse, err := handler.HTTPSRequest(ctx, tokenString, deleteAccommodationsEndpoint, "DELETE")
				if err != nil {
					span.SetStatus(codes.Error, "Error sending deleteAccommodationsRequest")
					log.Println("Error sending deleteAccommodationsRequest:", err)
					return nil, err
				}
				defer deleteAccommodationsResponse.Body.Close()

				if deleteAccommodationsResponse.StatusCode != http.StatusOK {
					span.SetStatus(codes.Error, "Error deleting accommodations")
					log.Println("Error deleting accommodations:", deleteAccommodationsResponse.Status)
					return nil, fmt.Errorf("Error deleting accommodations: %s", err)

				}

				return nil, nil
			})

			if breakerErr != nil {
				log.Println("Circuit breaker open:", breakerErr)
				span.SetStatus(codes.Error, "Service Unavailable")
				http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
				return
			}

			if _, ok := deleteAccommodationsResult.(error); ok {
				http.Error(writer, "Error deleting accommodations", http.StatusInternalServerError)
				span.SetStatus(codes.Error, "Error deleting accommodations")
				return
			}
		}
	} else if userType == "Guest" {
		// Circuit breaker for checking guest reservations
		hasReservationsResult, breakerErr := handler.cb.Execute(func() (interface{}, error) {
			return handler.hasGuestReservations(ctx, tokenString)
		})

		if breakerErr != nil {
			log.Println("Circuit breaker open:", breakerErr)
			span.SetStatus(codes.Error, "Service Unavailable")
			http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		hasReservations, ok = hasReservationsResult.(bool)
		if !ok {
			log.Println("Internal server error: Unexpected result type")
			span.SetStatus(codes.Error, "Internal server error")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	if hasReservations {
		http.Error(writer, "User has reservations, cannot delete account", http.StatusForbidden)
		span.SetStatus(codes.Error, "User has reservations, cannot delete account")
		return
	}

	// Circuit breaker for deleting user in user service
	deleteUserErrResult, breakerErr := handler.cb.Execute(func() (interface{}, error) {
		return nil, handler.userServiceDeleteUser(ctx, userID, tokenString)
	})

	if breakerErr != nil {
		log.Println("Circuit breaker open:", breakerErr)
		span.SetStatus(codes.Error, "Service Unavailable")
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	if _, ok := deleteUserErrResult.(error); ok {
		log.Println("User not found in user service")
		http.Error(writer, "User not found", http.StatusNotFound)
		span.SetStatus(codes.Error, "User not found in user service")
		return
	}

	status, statusCode, err := handler.service.DeleteUser(ctx, username)
	if err != nil {
		var errorMessage string

		switch status {
		case "baseErr":
			errorMessage = "Internal server error"
		case "UserServiceError":
			errorMessage = "User service is currently unavailable. Please try again later."
		default:
			errorMessage = "An error occurred"
		}

		span.SetStatus(codes.Error, "Error")
		http.Error(writer, errorMessage, statusCode)
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *AuthHandler) hasHostReservations(ctx context.Context, userID string, authToken string) (bool, error) {
	ctx, span := handler.tracer.Start(ctx, "AuthHandler.hasHostReservations")
	defer span.End()

	reservationEndpoint := fmt.Sprintf("https://%s:%s/reservationsByHost/%s", reservationServiceHost, reservationServicePort, userID)

	/*reservationRequest, err := http.NewRequest("GET", reservationEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(reservationRequest.Header))
	if err != nil {
		log.Println("Error creating reservation request:", err)
		span.SetStatus(codes.Error, "Error creating reservation request")
		return false, err
	}

	reservationRequest.Header.Set("Authorization", "Bearer "+authToken)*/

	reservationResponse, err := handler.HTTPSRequest(ctx, authToken, reservationEndpoint, "GET")
	if err != nil {
		log.Println("Error sending reservation request:", err)
		span.SetStatus(codes.Error, "Error sending reservation request")
		return false, err
	}

	if reservationResponse.StatusCode != http.StatusOK {
		log.Println(reservationResponse.StatusCode, reservationResponse)
		log.Printf("Error getting host reservations. Status code: %d\n", reservationResponse.StatusCode)
		span.SetStatus(codes.Error, "Error getting host reservations")
		return false, nil
	}

	defer reservationResponse.Body.Close()

	var hasReservations bool

	err = json.NewDecoder(reservationResponse.Body).Decode(&hasReservations)
	if err != nil {
		log.Println("Error decoding reservation response:", err)
		span.SetStatus(codes.Error, "Error decoding reservation response")
		return false, err
	}

	return hasReservations, nil
}

func (handler *AuthHandler) hasGuestReservations(ctx context.Context, authToken string) (bool, error) {
	ctx, span := handler.tracer.Start(ctx, "AuthHandler.hasGuestReservations")
	defer span.End()

	reservationEndpoint := fmt.Sprintf("https://%s:%s/reservationsByUser", reservationServiceHost, reservationServicePort)

	/*reservationRequest, err := http.NewRequest("GET", reservationEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(reservationRequest.Header))
	if err != nil {
		log.Println("Error creating reservation request:", err)
		span.SetStatus(codes.Error, "Error creating reservation request")
		return false, err
	}

	reservationRequest.Header.Set("Authorization", "Bearer "+authToken)*/

	reservationResponse, err := handler.HTTPSRequest(ctx, authToken, reservationEndpoint, "GET")
	if err != nil {
		log.Println("Error sending reservation request:", err)
		span.SetStatus(codes.Error, "Error sending reservation request")
		return false, err
	}

	if reservationResponse.StatusCode != http.StatusOK {
		log.Printf("Error getting guest reservations. Status code: %d\n", reservationResponse.StatusCode)
		span.SetStatus(codes.Error, "Error getting guest reservations")
		return false, err
	}

	body, err := ioutil.ReadAll(reservationResponse.Body)
	if err != nil {
		log.Println("Error reading response body:", err)
		span.SetStatus(codes.Error, "Error reading response body")
		return false, err
	}

	if len(body) == 0 {
		return false, nil
	}

	defer reservationResponse.Body.Close()
	return true, nil
}

func (handler *AuthHandler) getUserIDByUsername(ctx context.Context, username string, authToken string) (string, error) {
	ctx, span := handler.tracer.Start(ctx, "AuthHandler.getUserIDByUsername")
	defer span.End()

	userserviceEndpoint := fmt.Sprintf("https://%s:%s/getId/%s", userServiceHost, userServicePort, username)

	/*userserviceRequest, err := http.NewRequest("GET", userserviceEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(userserviceRequest.Header))
	if err != nil {
		log.Println("Error creating user request:", err)
		span.SetStatus(codes.Error, "Error creating user request")
		return "", err
	}

	userserviceRequest.Header.Set("Authorization", "Bearer "+authToken)*/

	userserviceResponse, err := handler.HTTPSRequest(ctx, authToken, userserviceEndpoint, "GET")
	if err != nil {
		log.Println("Error sending user request:", err)
		span.SetStatus(codes.Error, "Error sending user request")
		return "", err
	}

	defer userserviceResponse.Body.Close()

	if userserviceResponse.StatusCode != http.StatusOK {
		log.Printf("Error getting user ID. Status code: %d\n", userserviceResponse.StatusCode)
		span.SetStatus(codes.Error, "Error getting user ID")
		return "", err
	}

	var userID string

	err = json.NewDecoder(userserviceResponse.Body).Decode(&userID)
	if err != nil {
		log.Println("Error decoding user ID response:", err)
		span.SetStatus(codes.Error, "Error decoding user ID response")
		return "", err
	}

	return userID, nil
}

func (handler *AuthHandler) userServiceDeleteUser(ctx context.Context, userID string, authToken string) error {
	ctx, span := handler.tracer.Start(ctx, "AuthHandler.userServiceDeleteUser")
	defer span.End()

	userserviceEndpoint := fmt.Sprintf("https://%s:%s/%s/delete", userServiceHost, userServicePort, userID)

	/*userserviceRequest, err := http.NewRequest("DELETE", userserviceEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(userserviceRequest.Header))
	if err != nil {
		log.Println("Error creating user request:", err)
		span.SetStatus(codes.Error, "Error creating user request")
		return err
	}

	userserviceRequest.Header.Set("Authorization", "Bearer "+authToken)*/

	userserviceResponse, err := handler.HTTPSRequest(ctx, authToken, userserviceEndpoint, "DELETE")
	if err != nil {
		log.Println("Error sending user request:", err)
		span.SetStatus(codes.Error, "Error sending user request")
		return err
	}

	defer userserviceResponse.Body.Close()

	if userserviceResponse.StatusCode != http.StatusOK {
		log.Printf("Error deleting user. Status code: %d\n", userserviceResponse.StatusCode)
		span.SetStatus(codes.Error, "Error deleting user.")
		return err
	}

	return nil
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
func ExtractTraceInfoMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func CircuitBreaker(name string) *gobreaker.CircuitBreaker {
	return gobreaker.NewCircuitBreaker(
		gobreaker.Settings{
			Name:        name,
			MaxRequests: 1,
			Timeout:     10 * time.Second,
			Interval:    0,
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				return counts.ConsecutiveFailures > 2
			},
			OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
				log.Printf("Circuit Breaker '%s' changed from '%s' to '%s'\n", name, from, to)
			},

			IsSuccessful: func(err error) bool {
				if err == nil {
					return true
				}
				errResp, ok := err.(domain.ErrResp)
				return ok && errResp.StatusCode >= 400 && errResp.StatusCode < 500
			},
		},
	)
}

func (handler *AuthHandler) HTTPSRequest(ctx context.Context, token string, url string, method string) (*http.Response, error) {
	clientCertPath := "ca-cert.pem"

	clientCaCert, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(clientCaCert)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		CurvePreferences: []tls.CurveID{tls.CurveP521,
			tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return resp, nil
}
