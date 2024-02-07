package application

import (
	"auth_service/authorization"
	"auth_service/domain"
	"auth_service/errors"
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/cristalhq/jwt/v4"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/sony/gobreaker"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
	"io"
	"io/ioutil"
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
	store             domain.AuthStore
	cache             domain.AuthCache
	cb                *gobreaker.CircuitBreaker
	logger            *log.Logger
	writeError        func(msg string)
	writeInfo         func(msg string)
	writeRequestError func(r *http.Request, msg string)
	writeRequestInfo  func(r *http.Request, msg string)
}

func NewAuthService(l *log.Logger, e func(msg string), i func(msg string), re func(r *http.Request, msg string), ri func(r *http.Request, msg string), store domain.AuthStore, cache domain.AuthCache) *AuthService {
	return &AuthService{
		store:             store,
		cache:             cache,
		cb:                CircuitBreaker("authService"),
		logger:            l,
		writeError:        e,
		writeInfo:         i,
		writeRequestError: re,
		writeRequestInfo:  ri,
	}
}

func (service *AuthService) GetAll() ([]*domain.Credentials, error) {
	return service.store.GetAll()
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

func (service *AuthService) VerifyRecaptcha(recaptchaToken string) (bool, error) {
	recaptchaEndpoint := "https://www.google.com/recaptcha/api/siteverify"
	recaptchaSecret := recaptchaSecretKey

	// Pravimo zahtev ka reCAPTCHA API-ju
	response, err := http.Post(recaptchaEndpoint, "application/x-www-form-urlencoded",
		bytes.NewBuffer([]byte(fmt.Sprintf("secret=%s&response=%s", recaptchaSecret, recaptchaToken))))
	if err != nil {
		service.writeError(err.Error())
		return false, err
	}
	defer response.Body.Close()

	// ÄŚitamo odgovor od reCAPTCHA API-ja
	body, err := io.ReadAll(response.Body)
	if err != nil {
		service.writeError(err.Error())
		return false, err
	}

	// Parsiramo JSON odgovor
	var recaptchaResponse RecaptchaResponse
	if err := json.Unmarshal(body, &recaptchaResponse); err != nil {
		service.writeError(err.Error())
		return false, err
	}

	// Proveravamo da li je reCAPTCHA uspeĹˇno proverena i da li je postignut dobar rezultat
	if recaptchaResponse.Success /* && recaptchaResponse.Score >= 0.5*/ {
		return true, nil
	}

	log.Printf("ReCAPTCHA response: %v\n", recaptchaResponse)

	// Ako nije uspeĹˇna provera ili nije postignut dobar rezultat, vraÄ‡amo greĹˇku
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

func (service *AuthService) Register(user *domain.User) (string, int, error) {

	if err := validateUser(user); err != nil {
		return "", 400, err
	}
	checkUser, err := blackListChecking(user.Password)
	log.Println(checkUser)

	if checkUser {
		service.writeError("Password is in blacklist")
		log.Println("Password is in blacklist")
		return "", 406, fmt.Errorf("Password is in black list, try with another one!")
	}

	existingUser, err := service.store.GetOneUser(user.Username)
	if err != nil {
		service.writeError(err.Error())
		return "", 500, err
	}

	if existingUser != nil {
		service.writeError("UsernameExist")
		return "", 409, fmt.Errorf(errors.UsernameExist)
	}

	// Circuit breaker for email existence check
	/*result, breakerErr := service.cb.Execute(func() (interface{}, error) {
		userServiceEndpointMail := fmt.Sprintf("http://%s:%s/mailExist/%s", userServiceHost, userServicePort, user.Email)
		userServiceRequestMail, _ := http.NewRequest("GET", userServiceEndpointMail, nil)

		response, err := http.DefaultClient.Do(userServiceRequestMail)
		if err != nil {
			fmt.Println(err)
			return nil, fmt.Errorf("EmailServiceError")
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusNotFound {
			return nil, StatusError{Code: http.StatusMethodNotAllowed, Err: fmt.Errorf(errors.EmailAlreadyExist)}
		}

		return "EmailOK", nil
	})

	if breakerErr != nil {
		if statusErr, ok := breakerErr.(StatusError); ok {
			return "", statusErr.Code, statusErr.Err
		}
		return "", http.StatusServiceUnavailable, breakerErr
	}

	if result != nil {
		fmt.Println("Received meaningful data:", result)
	}*/
	pass := []byte(user.Password)
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
	if err != nil {
		service.writeError(err.Error())
		return "", 500, err
	}
	user.Password = string(hash)

	body, err := json.Marshal(user)
	if err != nil {
		service.writeError(err.Error())
		return "", 500, err
	}

	// Circuit breaker for user service request
	result, breakerErr := service.cb.Execute(func() (interface{}, error) {

		userServiceEndpoint := fmt.Sprintf("http://%s:%s/", userServiceHost, userServicePort)
		userServiceRequest, _ := http.NewRequest("POST", userServiceEndpoint, bytes.NewReader(body))

		responseUser, err := http.DefaultClient.Do(userServiceRequest)
		if err != nil {
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
			service.writeError(err.Error())
			return nil, err
		}

		credentials := domain.Credentials{
			ID:       newUser.ID,
			Username: user.Username,
			Password: user.Password,
			UserType: user.UserType,
			Verified: false,
		}

		err = service.store.Register(&credentials)
		if err != nil {
			service.writeError(err.Error())
			return nil, err
		}

		return "UserRegistered", nil
	})

	if breakerErr != nil {
		service.writeError("UserServiceError")
		return "UserServiceError", http.StatusServiceUnavailable, breakerErr
	}

	if result != nil {
		fmt.Println("Received meaningful data:", result)
	}

	validationToken := uuid.New()
	log.Printf("Username: %s", user.Username)
	log.Printf("Generated validation token: %s", validationToken.String())

	err = service.cache.PostCacheData(user.Username, validationToken.String())
	if err != nil {
		service.writeError(err.Error())
		log.Fatalf("Failed to post validation data to redis: %s", err)
		return "", 500, err
	}

	err = sendValidationMail(validationToken, user.Email)
	if err != nil {
		service.writeError(err.Error())
		return "", 500, err
	}

	return user.Username, 200, nil

}

func sendValidationMail(validationToken uuid.UUID, email string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", smtpEmail)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Verify your for airbnb account")

	bodyString := fmt.Sprintf("Your validation token for airbnb account is:\n%s", validationToken)
	m.SetBody("text", bodyString)

	client := gomail.NewDialer(smtpServer, smtpServerPort, smtpEmail, smtpPassword)

	if err := client.DialAndSend(m); err != nil {
		log.Fatalf("Failed to send verification mail because of: %s", err)
		return err
	}

	return nil
}

func (service *AuthService) AccountConfirmation(validation *domain.RegisterValidation) error {

	log.Printf("Validation token for verification: %s", validation.MailToken)
	token, err := service.cache.GetCachedValue(validation.UserToken)
	if err != nil {
		service.writeError(err.Error())
		log.Printf("Error fetching validation token from cache: %s", err)
		log.Println(errors.ExpiredTokenError)
		return fmt.Errorf(errors.ExpiredTokenError)
	}

	if validation.MailToken == token {
		err = service.cache.DelCachedValue(validation.UserToken)
		if err != nil {
			service.writeError(err.Error())
			log.Printf("Error in deleting cached value: %s", err)
			return err
		}

		log.Printf("validation.UserToken: %s", validation.UserToken)

		user, err := service.store.GetOneUser(validation.UserToken)
		if user == nil {
			log.Println("User is not found")
			return fmt.Errorf("User is not found")
		}
		user.Verified = true

		err = service.store.UpdateUserUsername(user)
		if err != nil {
			service.writeError(err.Error())
			log.Printf("Error in updating user after changing status of verify: %s", err.Error())
			return err
		}

		return nil
	}

	return fmt.Errorf(errors.InvalidTokenError)
}

func (service *AuthService) ResendVerificationToken(request *domain.ResendVerificationRequest) error {
	if len(request.UserMail) == 0 {
		log.Println(errors.InvalidResendMailError)
		return fmt.Errorf(errors.InvalidResendMailError)
	}

	tokenUUID, _ := uuid.NewUUID()

	err := service.cache.PostCacheData(request.UserToken, tokenUUID.String())
	if err != nil {
		service.writeError(err.Error())
		log.Println("Post cache problem")
		return err
	}

	err = sendValidationMail(tokenUUID, request.UserMail)
	if err != nil {
		service.writeError(err.Error())
		log.Println("Send verification mail problem")
		return err
	}

	return nil
}

func (service *AuthService) SendRecoveryPasswordToken(email string) (string, int, error) {
	// Circuit breaker for communication with user service
	result, breakerErr := service.cb.Execute(func() (interface{}, error) {
		userServiceEndpoint := fmt.Sprintf("http://%s:%s/mailExist/%s", userServiceHost, userServicePort, email)
		userServiceRequest, _ := http.NewRequest("GET", userServiceEndpoint, nil)
		response, err := http.DefaultClient.Do(userServiceRequest)
		if err != nil {
			service.writeError(err.Error())
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

		userDetailsEndpoint := fmt.Sprintf("http://%s:%s/%s", userServiceHost, userServicePort, userID)
		userDetailsRequest, _ := http.NewRequest("GET", userDetailsEndpoint, nil)
		userDetailsResponse, err := http.DefaultClient.Do(userDetailsRequest)
		if err != nil {
			return nil, fmt.Errorf("UserServiceError")
		}

		body, err := ioutil.ReadAll(userDetailsResponse.Body)
		if err != nil {
			service.writeError(err.Error())
			return nil, err
		}

		responseBodyString := string(body)
		log.Printf("User details response: %s", responseBodyString)

		var userDetails UserDetails
		err = json.Unmarshal(body, &userDetails)
		if err != nil {
			service.writeError(err.Error())
			fmt.Println("Error unmarshaling JSON:", err)
			return nil, err
		}

		fmt.Println("Username:", userDetails.Username)

		userUsernameCredentials, err := service.store.GetOneUser(userDetails.Username)
		if err != nil {
			service.writeError(err.Error())
			return nil, err
		}
		userID = userUsernameCredentials.ID.Hex()

		fmt.Println("Retrieved user ID:", userID)

		recoverUUID, _ := uuid.NewUUID()
		err = sendRecoverPasswordMail(recoverUUID, email)
		if err != nil {
			service.writeError(err.Error())
			return nil, err
		}

		err = service.cache.PostCacheData(userID, recoverUUID.String())
		if err != nil {
			service.writeError(err.Error())
			return nil, err
		}

		return userID, nil
	})

	if breakerErr != nil {
		service.writeError("StatusServiceUnavailable")
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

func sendRecoverPasswordMail(validationToken uuid.UUID, email string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", smtpEmail)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Recover password on your Airbnb account")

	bodyString := fmt.Sprintf("Your recover password token is:\n%s", validationToken)
	m.SetBody("text", bodyString)

	client := gomail.NewDialer(smtpServer, smtpServerPort, smtpEmail, smtpPassword)

	if err := client.DialAndSend(m); err != nil {
		log.Fatalf("failed to send verification mail because of: %s", err)
		return err
	}

	return nil
}

func (service *AuthService) CheckRecoveryPasswordToken(request *domain.RegisterValidation) error {

	if len(request.UserToken) == 0 {
		return fmt.Errorf(errors.InvalidUserTokenError)
	}

	token, err := service.cache.GetCachedValue(request.UserToken)
	if err != nil {
		service.writeError(err.Error())
		return fmt.Errorf(errors.InvalidTokenError)
	}

	if request.MailToken != token {
		return fmt.Errorf(errors.InvalidTokenError)
	}

	_ = service.cache.DelCachedValue(request.UserToken)
	return nil
}

func (service *AuthService) RecoverPassword(recoverPassword *domain.RecoverPasswordRequest) (string, int, error) {
	log.Println("Starting password recovery process...")

	if recoverPassword.NewPassword == "" {
		return "Password cannot be empty", http.StatusBadRequest, fmt.Errorf(errors.EmptyPassword)
	}
	if !verifyPassword(recoverPassword.NewPassword) {
		return "Invalid password format. It should be at least 11 characters, with at least one uppercase letter, one lowercase letter, one digit, and one special character", http.StatusBadRequest, fmt.Errorf(errors.InvalidPasswordFormat)
	}

	checkPassword, err := blackListChecking(recoverPassword.NewPassword)
	if err != nil {
		service.writeError(err.Error())
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
		log.Printf("Error converting user ID to ObjectID: %s", err)
		return "", http.StatusNotFound, err
	}

	log.Printf("Recovering password for user ID: %s", primitiveID.Hex())

	credentials := service.store.GetOneUserByID(primitiveID)
	if credentials == nil {
		log.Printf("User not found for ID: %s", primitiveID.Hex())
		return "", http.StatusNotFound, fmt.Errorf("User not found")
	}

	pass := []byte(recoverPassword.NewPassword)
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
	if err != nil {
		service.writeError(err.Error())
		return "Error trying to hash password.", http.StatusInternalServerError, err
	}
	credentials.Password = string(hash)

	err = service.store.UpdateUser(credentials)
	if err != nil {
		service.writeError(err.Error())
		return "baseErr", http.StatusInternalServerError, err
	}

	return "OK", http.StatusOK, nil
}

func (service *AuthService) ChangePassword(password domain.PasswordChange, token string) (string, int, error) {

	parsedToken := authorization.GetToken(token)
	claims := authorization.GetMapClaims(parsedToken.Bytes())

	username := claims["username"]

	user, err := service.store.GetOneUser(username)
	if err != nil {
		service.writeError(err.Error())
		log.Println(err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password.OldPassword))
	if err != nil {
		service.writeError(err.Error())
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
		service.writeError(err.Error())
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
			log.Println(err)
			return "Error trying to hash password.", http.StatusInternalServerError, err
		}

		user.Password = string(newEncryptedPassword)

		err = service.store.UpdateUser(user)
		if err != nil {
			service.writeError(err.Error())
			return "baseErr", http.StatusInternalServerError, err
		}

	} else {
		return "newPassErr", http.StatusNotAcceptable, fmt.Errorf("New password does not match confirmation")

	}

	return "OK", http.StatusOK, nil
}

func (service *AuthService) ChangeUsername(username domain.UsernameChange, token string) (string, int, error) {
	parsedToken := authorization.GetToken(token)
	claims := authorization.GetMapClaims(parsedToken.Bytes())

	currentUsername := claims["username"]
	fmt.Println("Current Username:", currentUsername)

	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]{4,30}$`)
	if !usernameRegex.MatchString(username.NewUsername) {
		return "InvalidUsername", http.StatusBadRequest, fmt.Errorf("Invalid username format. It must be 4-30 characters long and contain only letters, numbers, underscores, and hyphens")
	}

	existingUser, err := service.store.GetOneUser(username.NewUsername)
	if err != nil {
		service.writeError(err.Error())
		return "GetUserErr", http.StatusInternalServerError, err
	}

	if existingUser != nil {
		return "UsernameExist", http.StatusConflict, fmt.Errorf(errors.UsernameExist)
	}

	requestBody := map[string]interface{}{
		"old_username": currentUsername,
		"new_username": username.NewUsername,
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		service.writeError(err.Error())
		return "MarshalError", http.StatusInternalServerError, err
	}

	// Circuit breaker for communication with user service
	result, breakerErr := service.cb.Execute(func() (interface{}, error) {
		userServiceEndpoint := fmt.Sprintf("http://%s:%s/changeUsername", userServiceHost, userServicePort)
		userServiceRequest, _ := http.NewRequest("POST", userServiceEndpoint, bytes.NewReader(body))
		responseUser, err := http.DefaultClient.Do(userServiceRequest)

		if err != nil {
			service.writeError(err.Error())
			fmt.Println(err)
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
		return "UserServiceError", http.StatusServiceUnavailable, breakerErr
	}

	user, err := service.store.GetOneUser(currentUsername)
	if err != nil {
		service.writeError(err.Error())
		fmt.Println(err)
		return "GetUserErr", http.StatusInternalServerError, err
	}
	fmt.Println("Retrieved User:", user)

	user.Username = username.NewUsername

	err = service.store.UpdateUser(user)
	if err != nil {
		service.writeError(err.Error())
		return "baseErr", http.StatusInternalServerError, err
	}
	fmt.Println("Username Updated Successfully")

	return "OK", http.StatusOK, nil
}

func (service *AuthService) Login(credentials *domain.Credentials) (string, error) {
	user, err := service.store.GetOneUser(credentials.Username)
	if err != nil {
		service.writeError(err.Error())
		if err == sql.ErrNoRows {
			return "", fmt.Errorf(errors.InvalidCredentials)
		}
		return "", fmt.Errorf("Error retrieving user: %v", err)
	}

	if user == nil {
		return "", fmt.Errorf(errors.InvalidCredentials)
	}

	passError := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if passError != nil {
		return "not_same", err
	}

	tokenString, err := GenerateJWT(user)

	if err != nil {
		service.writeError(err.Error())
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

func (service *AuthService) DeleteUser(username string) (string, int, error) {
	existingUser, err := service.store.GetOneUser(username)
	if err != nil {
		service.writeError(err.Error())
		return "baseErr", http.StatusInternalServerError, err
	}

	if existingUser == nil {
		return "notFound", http.StatusNotFound, fmt.Errorf("User not found")
	}

	if err := service.store.DeleteUser(username); err != nil {
		service.writeError(err.Error())
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
		service.writeError(err.Error())
		return "", fmt.Errorf("Error parsing token: %s", err)
	}

	claims := token.Claims

	rawMessage := claims()

	byteSlice := []byte(rawMessage)

	var mapa map[string]interface{}
	err = json.Unmarshal(byteSlice, &mapa)
	if err != nil {
		service.writeError(err.Error())
		fmt.Println("GreĹˇka prilikom dekodiranja JSON-a:", err)
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
				//fmt.Printf("DEBUG: Before Circuit Breaker '%s' changed from '%s' to '%s'\n", name, from, to)
				log.Printf("Circuit Breaker '%s' changed from '%s' to '%s'\n", name, from, to)
				//fmt.Printf("DEBUG: After Circuit Breaker '%s' changed from '%s' to '%s'\n", name, from, to)
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
