package application

import (
	"auth_service/authorization"
	"auth_service/domain"
	"auth_service/errors"
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/cristalhq/jwt/v4"
	"github.com/google/uuid"
	"github.com/sony/gobreaker"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
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

var (
	userServiceHost    = os.Getenv("USER_SERVICE_HOST")
	userServicePort    = os.Getenv("USER_SERVICE_PORT")
	smtpServer         = "smtp.office365.com"
	smtpServerPort     = 587
	smtpEmail          = os.Getenv("SMTP_AUTH_MAIL")
	smtpPassword       = os.Getenv("SMTP_AUTH_PASSWORD")
	recaptchaSecretKey = os.Getenv("SECRET_CAPTCHA_KEY")
)

type AuthService struct {
	store  domain.AuthStore
	cache  domain.AuthCache
	cb     *gobreaker.CircuitBreaker
	tracer trace.Tracer
}

func NewAuthService(store domain.AuthStore, cache domain.AuthCache, tracer trace.Tracer) *AuthService {
	return &AuthService{
		store:  store,
		cache:  cache,
		cb:     CircuitBreaker("authService"),
		tracer: tracer,
	}
}

func (service *AuthService) GetAll(ctx context.Context) ([]*domain.Credentials, error) {
	ctx, span := service.tracer.Start(ctx, "AuthService.GetAll")
	defer span.End()

	return service.store.GetAll(ctx)
}

type ValidationError struct {
	Message string `json:"message"`
}

type RecaptchaResponse struct {
	Success     bool     `json:"success"`
	Score       float64  `json:"score"`
	Action      string   `json:"action"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

func (service *AuthService) VerifyRecaptcha(ctx context.Context, recaptchaToken string) (bool, error) {
	ctx, span := service.tracer.Start(ctx, "AuthService.VerifyRecaptcha")
	defer span.End()

	recaptchaEndpoint := "https://www.google.com/recaptcha/api/siteverify"
	recaptchaSecret := recaptchaSecretKey

	// Pravimo zahtev ka reCAPTCHA API-ju
	response, err := http.Post(recaptchaEndpoint, "application/x-www-form-urlencoded",
		bytes.NewBuffer([]byte(fmt.Sprintf("secret=%s&response=%s", recaptchaSecret, recaptchaToken))))
	if err != nil {
		span.SetStatus(codes.Error, "Error")
		return false, err
	}
	defer response.Body.Close()

	// Čitamo odgovor od reCAPTCHA API-ja
	body, err := io.ReadAll(response.Body)
	if err != nil {
		span.SetStatus(codes.Error, "Error")
		return false, err
	}

	// Parsiramo JSON odgovor
	var recaptchaResponse RecaptchaResponse
	if err := json.Unmarshal(body, &recaptchaResponse); err != nil {
		span.SetStatus(codes.Error, "Error unmarshal body")
		return false, err
	}

	// Proveravamo da li je reCAPTCHA uspešno proverena i da li je postignut dobar rezultat
	if recaptchaResponse.Success /* && recaptchaResponse.Score >= 0.5*/ {
		return true, nil
	}

	log.Printf("ReCAPTCHA response: %v\n", recaptchaResponse)

	// Ako nije uspešna provera ili nije postignut dobar rezultat, vraćamo grešku
	span.SetStatus(codes.Error, "Invalid reCAPTCHA token or low score")
	return false, fmt.Errorf("Invalid reCAPTCHA token or low score")
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

type StatusError struct {
	Code int
	Err  error
}

// Error interface for StatusError for Circuit Breaker
func (se StatusError) Error() string {
	return fmt.Sprintf("HTTP Status %d: %s", se.Code, se.Err.Error())
}

func (service *AuthService) Register(ctx context.Context, user *domain.User) (string, int, error) {
	ctx, span := service.tracer.Start(ctx, "AuthService.Register")
	defer span.End()
	if err := validateUser(user); err != nil {
		span.SetStatus(codes.Error, "Error validating user")
		return "", 400, err
	}
	checkUser, err := blackListChecking(user.Password)
	log.Println(checkUser)

	if checkUser {
		log.Println("Password is in blacklist")
		span.SetStatus(codes.Error, err.Error())
		return "", 406, fmt.Errorf("Password is in black list, try with another one!")
	}

	existingUser, err := service.store.GetOneUser(ctx, user.Username)
	if err != nil {
		span.SetStatus(codes.Error, "That user already exists")
		return "", 500, err
	}

	if existingUser != nil {
		//span.SetStatus(codes.Error, err.Error())
		return "", 409, fmt.Errorf(errors.UsernameExist)
	}

	// Circuit breaker for email existence check
	/*result, breakerErr := service.cb.Execute(func() (interface{}, error) {
		userServiceEndpointMail := fmt.Sprintf("https://%s:%s/mailExist/%s", userServiceHost, userServicePort, user.Email)
		response, err := service.HTTPSRequestGetToken(ctx, userServiceEndpointMail, "GET")
		if err != nil {
			span.SetStatus(codes.Error, "Email service error")
			fmt.Println(err)
			return nil, fmt.Errorf("EmailServiceError")
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusNotFound {
			span.SetStatus(codes.Error, "Email already exist")
			return nil, StatusError{Code: http.StatusMethodNotAllowed, Err: fmt.Errorf(errors.EmailAlreadyExist)}
		}

		return "EmailOK", nil
	})

	if breakerErr != nil {
		if statusErr, ok := breakerErr.(StatusError); ok {
			span.SetStatus(codes.Error, "Breaker error")
			return "", statusErr.Code, statusErr.Err
		}
		span.SetStatus(codes.Error, "Service is unavailable")
		return "", http.StatusServiceUnavailable, breakerErr
	}

	if result != nil {
		span.SetStatus(codes.Error, err.Error())
		fmt.Println("Received meaningful data:", result)
	}*/
	pass := []byte(user.Password)
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
	if err != nil {
		span.SetStatus(codes.Error, "Error hashing the password")
		return "", 500, err
	}
	user.Password = string(hash)

	requestBody := map[string]interface{}{
		"id":        user.ID,
		"firstName": user.FirstName,
		"lastName":  user.LastName,
		"gender":    user.Gender,
		"age":       user.Age,
		"residence": user.Residence,
		"email":     user.Email,
		"username":  user.Username,
		"userType":  user.UserType,
	}

	// Circuit breaker for user service request
	result, breakerErr := service.cb.Execute(func() (interface{}, error) {
		userServiceEndpoint := fmt.Sprintf("https://%s:%s/", userServiceHost, userServicePort)
		responseUser, err := service.HTTPSRequestWithoutToken(ctx, userServiceEndpoint, "POST", requestBody)
		if err != nil {
			span.SetStatus(codes.Error, "UserServiceError")
			return nil, fmt.Errorf("UserServiceError")
		}
		defer responseUser.Body.Close()

		if responseUser.StatusCode != http.StatusOK {
			buf := new(strings.Builder)
			_, _ = io.Copy(buf, responseUser.Body)
			return nil, fmt.Errorf(buf.String())
		}

		var newUser domain.User

		err = responseToType(responseUser.Body, newUser)
		if err != nil {
			span.SetStatus(codes.Error, "Error response to type")
			return nil, err
		}

		credentials := domain.Credentials{
			ID:       newUser.ID,
			Username: user.Username,
			Password: user.Password,
			UserType: user.UserType,
			Verified: false,
		}

		err = service.store.Register(ctx, &credentials)
		if err != nil {
			span.SetStatus(codes.Error, "Error register user")
			return nil, err
		}

		return "UserRegistered", nil
	})

	if breakerErr != nil {
		span.SetStatus(codes.Error, "UserServiceError")
		return "UserServiceError", http.StatusServiceUnavailable, breakerErr
	}

	if result != nil {
		fmt.Println("Received meaningful data:", result)
	}

	validationToken := uuid.New()
	log.Printf("Username: %s", user.Username)
	log.Printf("Generated validation token: %s", validationToken.String())

	err = service.cache.PostCacheData(ctx, user.Username, validationToken.String())
	if err != nil {
		span.SetStatus(codes.Error, "Failed to post validation data to redis")
		log.Fatalf("Failed to post validation data to redis: %s", err)
		return "", 500, err
	}

	err = service.sendValidationMail(ctx, validationToken, user.Email)
	if err != nil {
		span.SetStatus(codes.Error, "Failed to send mail")
		return "", 500, err
	}

	return user.Username, 200, nil

}

func (service *AuthService) sendValidationMail(ctx context.Context, validationToken uuid.UUID, email string) error {
	ctx, span := service.tracer.Start(ctx, "AuthService.sendValidationMail")
	defer span.End()

	m := gomail.NewMessage()
	m.SetHeader("From", smtpEmail)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Verify your for airbnb account")

	bodyString := fmt.Sprintf("Your validation token for airbnb account is:\n%s", validationToken)
	m.SetBody("text", bodyString)

	client := gomail.NewDialer(smtpServer, smtpServerPort, smtpEmail, smtpPassword)

	if err := client.DialAndSend(m); err != nil {
		span.SetStatus(codes.Error, "Failed to send verification mail")
		log.Fatalf("Failed to send verification mail because of: %s", err)
		return err
	}

	return nil
}

func (service *AuthService) AccountConfirmation(ctx context.Context, validation *domain.RegisterValidation) error {
	ctx, span := service.tracer.Start(ctx, "AuthService.VerifyAccount")
	defer span.End()
	log.Printf("Validation token for verification: %s", validation.MailToken)
	token, err := service.cache.GetCachedValue(ctx, validation.UserToken)
	if err != nil {
		span.SetStatus(codes.Error, "Error fetching validation token from cache")
		log.Printf("Error fetching validation token from cache: %s", err)
		log.Println(errors.ExpiredTokenError)
		return fmt.Errorf(errors.ExpiredTokenError)
	}

	if validation.MailToken == token {
		err = service.cache.DelCachedValue(ctx, validation.UserToken)
		if err != nil {
			span.SetStatus(codes.Error, "Error in deleting cached value")
			log.Printf("Error in deleting cached value: %s", err)
			return err
		}

		log.Printf("validation.UserToken: %s", validation.UserToken)

		user, err := service.store.GetOneUser(ctx, validation.UserToken)
		if user == nil {
			span.SetStatus(codes.Error, "User is not found")
			log.Println("User is not found")
			return fmt.Errorf("User is not found")
		}
		user.Verified = true

		err = service.store.UpdateUserUsername(ctx, user)
		if err != nil {
			span.SetStatus(codes.Error, "Error in updating user after changing status of verify")
			log.Printf("Error in updating user after changing status of verify: %s", err.Error())
			return err
		}

		return nil
	}

	span.SetStatus(codes.Error, "Invalid token error")
	return fmt.Errorf(errors.InvalidTokenError)
}

func (service *AuthService) ResendVerificationToken(ctx context.Context, request *domain.ResendVerificationRequest) error {
	ctx, span := service.tracer.Start(ctx, "AuthService.ResendVerificationToken")
	defer span.End()

	if len(request.UserMail) == 0 {
		log.Println(errors.InvalidResendMailError)
		return fmt.Errorf(errors.InvalidResendMailError)
	}

	tokenUUID, _ := uuid.NewUUID()

	err := service.cache.PostCacheData(ctx, request.UserToken, tokenUUID.String())
	if err != nil {
		span.SetStatus(codes.Error, "Post cache problem")
		log.Println("Post cache problem")
		return err
	}

	err = service.sendValidationMail(ctx, tokenUUID, request.UserMail)
	if err != nil {
		span.SetStatus(codes.Error, "Send verification mail problem")
		log.Println("Send verification mail problem")
		return err
	}

	return nil
}

func (service *AuthService) SendRecoveryPasswordToken(ctx context.Context, email string) (string, int, error) {
	ctx, span := service.tracer.Start(ctx, "AuthService.SendRecoveryPasswordToken")
	defer span.End()
	// Circuit breaker for communication with user service
	result, breakerErr := service.cb.Execute(func() (interface{}, error) {
		url := fmt.Sprintf("https://%s:%s/mailExist/%s", userServiceHost, userServicePort, email)
		response, err := service.HTTPSRequestGetToken(ctx, url, "GET")
		if err != nil {
			span.SetStatus(codes.Error, "EmailServiceError")
			return nil, fmt.Errorf("EmailServiceError")
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			if response.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf(errors.NotFoundMailError)
			}
			buf := new(strings.Builder)
			_, _ = io.Copy(buf, response.Body)
			return nil, fmt.Errorf(buf.String())
		}

		buf := new(strings.Builder)
		_, _ = io.Copy(buf, response.Body)
		userID := buf.String()

		userDetailsEndpoint := fmt.Sprintf("https://%s:%s/%s", userServiceHost, userServicePort, userID)
		userDetailsResponse, err := service.HTTPSRequestGetToken(ctx, userDetailsEndpoint, "GET")
		if err != nil {
			span.SetStatus(codes.Error, "UserServiceError")
			return nil, fmt.Errorf("UserServiceError")
		}

		body, err := ioutil.ReadAll(userDetailsResponse.Body)
		if err != nil {
			span.SetStatus(codes.Error, "Error reading user details response")
			return nil, err
		}

		responseBodyString := string(body)
		log.Printf("User details response: %s", responseBodyString)

		var userDetails UserDetails
		err = json.Unmarshal(body, &userDetails)
		if err != nil {
			span.SetStatus(codes.Error, "Error unmarshalling JSON")
			fmt.Println("Error unmarshalling JSON:", err)
			return nil, err
		}

		fmt.Println("Username:", userDetails.Username)

		userUsernameCredentials, err := service.store.GetOneUser(ctx, userDetails.Username)
		if err != nil {
			span.SetStatus(codes.Error, "Error getting user")
			return nil, err
		}
		userID = userUsernameCredentials.ID.Hex()

		fmt.Println("Retrieved user ID:", userID)

		recoverUUID, _ := uuid.NewUUID()
		err = service.sendRecoverPasswordMail(ctx, recoverUUID, email)
		if err != nil {
			span.SetStatus(codes.Error, "Error sending mail")
			return nil, err
		}

		err = service.cache.PostCacheData(ctx, userID, recoverUUID.String())
		if err != nil {
			span.SetStatus(codes.Error, "Error posting cache data")
			return nil, err
		}

		return userID, nil
	})

	if breakerErr != nil {
		return "", http.StatusServiceUnavailable, breakerErr
	}

	if result != nil {
		fmt.Println("Received meaningful data:", result)
	}

	return result.(string), http.StatusOK, nil
}

type UserDetails struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Gender    string `json:"gender"`
	Age       int    `json:"age"`
	Residence string `json:"residence"`
	Email     string `json:"email"`
	UserType  string `json:"userType"`
}

func (service *AuthService) sendRecoverPasswordMail(ctx context.Context, validationToken uuid.UUID, email string) error {
	ctx, span := service.tracer.Start(ctx, "AuthService.sendValidationMail")
	defer span.End()

	m := gomail.NewMessage()
	m.SetHeader("From", smtpEmail)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Recover password on your Airbnb account")

	bodyString := fmt.Sprintf("Your recover password token is:\n%s", validationToken)
	m.SetBody("text", bodyString)

	client := gomail.NewDialer(smtpServer, smtpServerPort, smtpEmail, smtpPassword)

	if err := client.DialAndSend(m); err != nil {
		span.SetStatus(codes.Error, "failed to send verification mail")
		log.Fatalf("failed to send verification mail because of: %s", err)
		return err
	}

	return nil
}

func (service *AuthService) CheckRecoveryPasswordToken(ctx context.Context, request *domain.RegisterValidation) error {
	ctx, span := service.tracer.Start(ctx, "AuthService.CheckRecoveryPasswordToken")
	defer span.End()

	if len(request.UserToken) == 0 {
		return fmt.Errorf(errors.InvalidUserTokenError)
	}

	token, err := service.cache.GetCachedValue(ctx, request.UserToken)
	if err != nil {
		span.SetStatus(codes.Error, "Invalid token error")
		return fmt.Errorf(errors.InvalidTokenError)
	}

	if request.MailToken != token {
		span.SetStatus(codes.Error, "Invalid token error")
		return fmt.Errorf(errors.InvalidTokenError)
	}

	_ = service.cache.DelCachedValue(ctx, request.UserToken)
	return nil
}

func (service *AuthService) RecoverPassword(ctx context.Context, recoverPassword *domain.RecoverPasswordRequest) (string, int, error) {
	ctx, span := service.tracer.Start(ctx, "AuthService.RecoverPassword")
	defer span.End()

	log.Println("Starting password recovery process...")

	if recoverPassword.NewPassword == "" {
		return "Password cannot be empty", http.StatusBadRequest, fmt.Errorf(errors.EmptyPassword)
	}
	if !verifyPassword(recoverPassword.NewPassword) {
		return "Invalid password format. It should be at least 11 characters, with at least one uppercase letter, one lowercase letter, one digit, and one special character", http.StatusBadRequest, fmt.Errorf(errors.InvalidPasswordFormat)
	}

	checkPassword, err := blackListChecking(recoverPassword.NewPassword)
	if err != nil {
		span.SetStatus(codes.Error, "Error checking password against blacklist")
		log.Println(err)
		return "Error checking password against blacklist", http.StatusInternalServerError, err
	}

	if checkPassword {
		log.Println("Password is in the blacklist")
		return "Password is in the blacklist", http.StatusBadRequest, fmt.Errorf(errors.BlackList)
	}

	if recoverPassword.NewPassword != recoverPassword.RepeatedNew {
		return "newPassErr", http.StatusNotAcceptable, fmt.Errorf(errors.NotMatchingPasswordsError)
	}

	primitiveID, err := primitive.ObjectIDFromHex(recoverPassword.UserID)
	if err != nil {
		span.SetStatus(codes.Error, "Error converting user ID to ObjectID")
		log.Printf("Error converting user ID to ObjectID: %s", err)
		return "", http.StatusNotFound, err
	}

	log.Printf("Recovering password for user ID: %s", primitiveID.Hex())

	credentials := service.store.GetOneUserByID(ctx, primitiveID)
	if credentials == nil {
		span.SetStatus(codes.Error, "User not found")
		log.Printf("User not found for ID: %s", primitiveID.Hex())
		return "", http.StatusNotFound, fmt.Errorf("User not found")
	}

	pass := []byte(recoverPassword.NewPassword)
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
	if err != nil {
		span.SetStatus(codes.Error, "Error trying to hash password.")
		return "Error trying to hash password.", http.StatusInternalServerError, err
	}
	credentials.Password = string(hash)

	err = service.store.UpdateUser(ctx, credentials)
	if err != nil {
		span.SetStatus(codes.Error, "Internal server error")
		return "baseErr", http.StatusInternalServerError, err
	}

	return "OK", http.StatusOK, nil
}

func (service *AuthService) ChangePassword(ctx context.Context, password domain.PasswordChange, token string) (string, int, error) {
	ctx, span := service.tracer.Start(ctx, "AuthService.ChangePassword")
	defer span.End()

	parsedToken := authorization.GetToken(token)
	claims := authorization.GetMapClaims(parsedToken.Bytes())

	username := claims["username"]

	user, err := service.store.GetOneUser(ctx, username)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting user")
		log.Println(err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password.OldPassword))
	if err != nil {
		span.SetStatus(codes.Error, "Old password is incorrect")
		return "oldPassErr", http.StatusConflict, fmt.Errorf("Old password is incorrect")
	}

	if password.NewPassword == "" {
		return "Password cannot be empty", http.StatusBadRequest, fmt.Errorf("New password is empty")
	}
	if !verifyPassword(password.NewPassword) {
		return "Invalid password format. It should be at least 11 characters, with at least one uppercase letter, one lowercase letter, one digit, and one special character", http.StatusBadRequest, fmt.Errorf("Invalid password format")
	}

	checkPassword, err := blackListChecking(password.NewPassword)
	if err != nil {
		span.SetStatus(codes.Error, "Error checking password against blacklist")
		log.Println(err)
		return "Error checking password against blacklist", http.StatusInternalServerError, err
	}

	if checkPassword {
		log.Println("Password is in the blacklist")
		return "Password is in the blacklist", http.StatusBadRequest, fmt.Errorf(errors.BlackList)
	}

	var isNewPasswordValid bool = false
	fmt.Println(password)
	if password.NewPassword == password.NewPasswordConfirm {
		isNewPasswordValid = true
	}

	if isNewPasswordValid {
		newEncryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			span.SetStatus(codes.Error, "Error trying to hash password.")
			log.Println(err)
			return "Error trying to hash password.", http.StatusInternalServerError, err
		}

		user.Password = string(newEncryptedPassword)

		err = service.store.UpdateUser(ctx, user)
		if err != nil {
			span.SetStatus(codes.Error, "Internal server error")
			return "baseErr", http.StatusInternalServerError, err
		}

	} else {
		span.SetStatus(codes.Error, "New password does not match confirmation")
		return "newPassErr", http.StatusNotAcceptable, fmt.Errorf("New password does not match confirmation")

	}

	return "OK", http.StatusOK, nil
}

func (service *AuthService) ChangeUsername(ctx context.Context, username domain.UsernameChange, token string) (string, int, error) {
	ctx, span := service.tracer.Start(ctx, "AuthService.ChangePassword")
	defer span.End()

	parsedToken := authorization.GetToken(token)
	claims := authorization.GetMapClaims(parsedToken.Bytes())

	currentUsername := claims["username"]
	fmt.Println("Current Username:", currentUsername)

	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]{4,30}$`)
	if !usernameRegex.MatchString(username.NewUsername) {
		return "InvalidUsername", http.StatusBadRequest, fmt.Errorf("Invalid username format. It must be 4-30 characters long and contain only letters, numbers, underscores, and hyphens")
	}

	existingUser, err := service.store.GetOneUser(ctx, username.NewUsername)
	if err != nil {
		span.SetStatus(codes.Error, "Internal server error")
		return "GetUserErr", http.StatusInternalServerError, err
	}

	if existingUser != nil {
		return "UsernameExist", http.StatusConflict, fmt.Errorf(errors.UsernameExist)
	}

	requestBody := map[string]interface{}{
		"old_username": currentUsername,
		"new_username": username.NewUsername,
	}

	// Circuit breaker for communication with user service
	result, breakerErr := service.cb.Execute(func() (interface{}, error) {
		url := fmt.Sprintf("http://%s:%s/changeUsername", userServiceHost, userServicePort)
		responseUser, err := service.HTTPSRequest(ctx, token, url, "POST", requestBody)

		if err != nil {
			fmt.Println(err)
			span.SetStatus(codes.Error, "UserServiceError")
			return nil, fmt.Errorf("UserServiceError")
		}
		defer responseUser.Body.Close()

		if responseUser.StatusCode != http.StatusOK {
			buf := new(strings.Builder)
			_, _ = io.Copy(buf, responseUser.Body)
			return nil, fmt.Errorf(buf.String())
		}

		return nil, nil
	})

	if result != nil {

		fmt.Println("Received meaningful data:", result)
	}
	if breakerErr != nil {
		span.SetStatus(codes.Error, "UserServiceError")
		return "UserServiceError", http.StatusServiceUnavailable, breakerErr
	}

	user, err := service.store.GetOneUser(ctx, currentUsername)
	if err != nil {
		fmt.Println(err)
		span.SetStatus(codes.Error, "GetUserErr")
		return "GetUserErr", http.StatusInternalServerError, err
	}
	fmt.Println("Retrieved User:", user)

	user.Username = username.NewUsername

	err = service.store.UpdateUser(ctx, user)
	if err != nil {
		span.SetStatus(codes.Error, "Internal server error")
		return "baseErr", http.StatusInternalServerError, err
	}
	fmt.Println("Username Updated Successfully")

	return "OK", http.StatusOK, nil
}

func (service *AuthService) Login(ctx context.Context, credentials *domain.Credentials) (string, error) {
	ctx, span := service.tracer.Start(ctx, "AuthService.Login")
	defer span.End()
	user, err := service.store.GetOneUser(ctx, credentials.Username)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		if err == sql.ErrNoRows {
			span.SetStatus(codes.Error, "Invalid credentials")
			return "", fmt.Errorf(errors.InvalidCredentials)
		}
		return "", fmt.Errorf("Error retrieving user: %v", err)
	}

	if user == nil {
		span.SetStatus(codes.Error, "Invalid credentials")
		return "", fmt.Errorf(errors.InvalidCredentials)
	}

	passError := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if passError != nil {
		span.SetStatus(codes.Error, "Invalid password")
		return "not_same", err
	}

	tokenString, err := GenerateJWT(user)

	if err != nil {
		span.SetStatus(codes.Error, "Error")
		return "", err
	}

	return tokenString, nil
}

func responseToType(response io.ReadCloser, any any) error {
	responseBodyBytes, err := io.ReadAll(response)
	if err != nil {
		log.Printf("err in readAll %s", err.Error())
		return err
	}

	err = json.Unmarshal(responseBodyBytes, &any)
	if err != nil {
		log.Printf("err in Unmarshal %s", err.Error())
		return err
	}

	return nil
}

func (service *AuthService) DeleteUser(ctx context.Context, username string) (string, int, error) {
	ctx, span := service.tracer.Start(ctx, "AuthService.Login")
	defer span.End()

	existingUser, err := service.store.GetOneUser(ctx, username)
	if err != nil {
		span.SetStatus(codes.Error, "Internal server error")
		return "baseErr", http.StatusInternalServerError, err
	}

	if existingUser == nil {
		return "notFound", http.StatusNotFound, fmt.Errorf("User not found")
	}

	if err := service.store.DeleteUser(ctx, username); err != nil {
		span.SetStatus(codes.Error, "Internal server error")
		return "baseErr", http.StatusInternalServerError, err
	}

	return "OK", http.StatusOK, nil
}

func GenerateJWT(user *domain.Credentials) (string, error) {

	key := []byte(os.Getenv("SECRET_KEY"))
	signer, err := jwt.NewSignerHS(jwt.HS256, key)
	if err != nil {
		log.Println(err)
	}

	builder := jwt.NewBuilder(signer)

	claims := &domain.Claims{
		Username:  user.Username,
		Role:      user.UserType,
		ExpiresAt: time.Now().Add(time.Minute * 60),
	}

	token, err := builder.Build(claims)
	if err != nil {
		log.Println(err)
	}

	return token.String(), nil
}

func (service *AuthService) ExtractUsernameFromToken(tokenString string) (string, error) {
	verifier, _ := jwt.NewVerifierHS(jwt.HS256, []byte(os.Getenv("SECRET_KEY")))

	token, err := jwt.Parse([]byte(tokenString), verifier)
	if err != nil {
		return "", fmt.Errorf("Error parsing token: %s", err)
	}

	claims := token.Claims

	rawMessage := claims()

	byteSlice := []byte(rawMessage)

	var mapa map[string]interface{}
	err = json.Unmarshal(byteSlice, &mapa)
	if err != nil {
		fmt.Println("Greška prilikom dekodiranja JSON-a:", err)
		return "", fmt.Errorf("Error decoding token")
	}

	username, ok := mapa["username"].(string)
	if !ok {
		return "", fmt.Errorf("Username not found in token claims")
	}

	return username, nil
}

func blackListChecking(username string) (bool, error) {

	file, err := os.Open("blacklist.txt")

	if err != nil {
		log.Printf("Error in checking blacklist: %s", err.Error())
		return false, err
	}
	defer file.Close()

	blacklist := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		blacklist[scanner.Text()] = true
	}
	if blacklist[username] {
		return true, nil
	} else {
		return false, nil
	}
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

func (service *AuthService) HTTPSRequest(ctx context.Context, token string, url string, method string, requestBody interface{}) (*http.Response, error) {
	clientCertPath := "ca-cert.pem"

	clientCaCert, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(clientCaCert)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		RootCAs: caCertPool,
		//ServerName: "user_service",
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

	body, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
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

func (service *AuthService) HTTPSRequestWithoutToken(ctx context.Context, url string, method string, requestBody interface{}) (*http.Response, error) {
	clientCertPath := "ca-cert.pem"

	clientCaCert, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(clientCaCert)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		RootCAs: caCertPool,
		//ServerName: "user_service",
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

	body, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (service *AuthService) HTTPSRequestGetToken(ctx context.Context, url string, method string) (*http.Response, error) {
	clientCertPath := "ca-cert.pem"

	clientCaCert, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(clientCaCert)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		RootCAs: caCertPool,
		//ServerName: "user_service",
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

	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return resp, nil
}
