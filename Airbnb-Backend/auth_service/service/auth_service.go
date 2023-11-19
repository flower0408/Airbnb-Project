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
	"go.mongodb.org/mongo-driver/bson/primitive"
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
	userServiceHost = os.Getenv("USER_SERVICE_HOST")
	userServicePort = os.Getenv("USER_SERVICE_PORT")
	smtpServer      = "smtp.office365.com"
	smtpServerPort  = 587
	smtpEmail       = os.Getenv("SMTP_AUTH_MAIL")
	smtpPassword    = os.Getenv("SMTP_AUTH_PASSWORD")
)

type AuthService struct {
	store domain.AuthStore
	cache domain.AuthCache
}

func NewAuthService(store domain.AuthStore, cache domain.AuthCache) *AuthService {
	return &AuthService{
		store: store,
		cache: cache,
	}
}

func (service *AuthService) GetAll() ([]*domain.Credentials, error) {
	return service.store.GetAll()
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
	residenceRegex := regexp.MustCompile(`^[a-zA-Z0-9\s,'-]{3,35}$`)
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]{4,30}$`)

	// Validate Email
	if user.Email == "" {
		return &ValidationError{Message: "Email cannot be empty"}
	}
	if !emailRegex.MatchString(user.Email) {
		return &ValidationError{Message: "Invalid email format"}
	}

	// Validate FirstName and LastName
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

	// Validate Password
	if user.Password == "" {
		return &ValidationError{Message: "Password cannot be empty"}
	}
	if !verifyPassword(user.Password) {
		return &ValidationError{Message: "Invalid password format. It should be at least 11 characters, with at least one uppercase letter, one lowercase letter, one digit, and one special character"}
	}

	// Validate Username
	if user.Username == "" {
		return &ValidationError{Message: "Username cannot be empty"}
	}
	if !usernameRegex.MatchString(user.Username) {
		return &ValidationError{Message: "Invalid username format. It must be 4-30 characters long and contain only letters, numbers, underscores, and hyphens"}
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

func (service *AuthService) Register(user *domain.User) (string, int, error) {

	if err := validateUser(user); err != nil {
		return "", 400, err
	}
	checkUser, err := blackListChecking(user.Password)
	log.Println(checkUser)

	if checkUser {
		log.Println("Password is in blacklist")
		return "", 55, fmt.Errorf("Password is in black list, try with another one!")
	}

	/* PAZI OVDE OVO JE TRENUTNO ZAKOMENTARISANO - PROVERA DA NE POSTOJI USER SA ISTIM MAILOM
	existingUser, err := service.store.GetOneUser(user.Username)
	if err != nil {
		return "", 500, err
	}

	if existingUser != nil {
		return "", 409, fmt.Errorf(errors.UsernameExist)
	}

	userServiceEndpointMail := fmt.Sprintf("http://%s:%s/mailExist/%s", userServiceHost, userServicePort, user.Email)
	userServiceRequestMail, _ := http.NewRequest("GET", userServiceEndpointMail, nil)
	response, _ := http.DefaultClient.Do(userServiceRequestMail)
	if response.StatusCode != 404 {
		return "", 406, fmt.Errorf(errors.EmailAlreadyExist)
	}
	*/
	pass := []byte(user.Password)
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
	if err != nil {
		return "", 500, err
	}
	user.Password = string(hash)

	body, err := json.Marshal(user)
	if err != nil {
		return "", 500, err
	}

	userServiceEndpoint := fmt.Sprintf("http://%s:%s/", userServiceHost, userServicePort)
	userServiceRequest, _ := http.NewRequest("POST", userServiceEndpoint, bytes.NewReader(body))
	responseUser, err := http.DefaultClient.Do(userServiceRequest)

	if responseUser.StatusCode != 200 {
		buf := new(strings.Builder)
		_, _ = io.Copy(buf, responseUser.Body)
		return "", responseUser.StatusCode, fmt.Errorf(buf.String())
	}

	var newUser domain.User
	err = responseToType(responseUser.Body, newUser)
	if err != nil {
		return "", 500, err
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
		return "", 500, err
	}

	/*  OVDE JE POKUSANO SA ID-EM DA SE URADI ALI KONVERZIJA NE RADI IZ NEKOG RAZLOGA
	validationToken := uuid.New()
	log.Printf("User ID (Hex): %s", newUser.ID.Hex())
	log.Printf("Generated validation token: %s", validationToken.String())

	err = service.cache.PostCacheData(newUser.ID.Hex(), validationToken.String())
	if err != nil {
		log.Fatalf("Failed to post validation data to redis: %s", err)
		return "", 500, err
	}

	err = sendValidationMail(validationToken, user.Email)
	if err != nil {
		return "", 500, err
	}

	return newUser.ID.Hex(), 200, nil*/
	validationToken := uuid.New()
	log.Printf("Username: %s", user.Username)
	log.Printf("Generated validation token: %s", validationToken.String())

	err = service.cache.PostCacheData(user.Username, validationToken.String())
	if err != nil {
		log.Fatalf("Failed to post validation data to redis: %s", err)
		return "", 500, err
	}

	err = sendValidationMail(validationToken, user.Email)
	if err != nil {
		return "", 500, err
	}

	return user.Username, 200, nil

}

func sendValidationMail(validationToken uuid.UUID, email string) error {
	message := gomail.NewMessage()
	message.SetHeader("From", smtpEmail)
	message.SetHeader("To", email)
	message.SetHeader("Subject", "Verify your for airbnb account")

	bodyString := fmt.Sprintf("Your validation token for airbnb account is:\n%s", validationToken)
	message.SetBody("text", bodyString)

	client := gomail.NewDialer(smtpServer, smtpServerPort, smtpEmail, smtpPassword)

	if err := client.DialAndSend(message); err != nil {
		log.Fatalf("failed to send verification mail because of: %s", err)
		return err
	}

	return nil
}

func (service *AuthService) AccountConfirmation(validation *domain.RegisterValidation) error {

	log.Printf("Validation token for verification: %s", validation.MailToken)
	token, err := service.cache.GetCachedValue(validation.UserToken)
	if err != nil {
		log.Printf("Error fetching validation token from cache: %s", err)
		log.Println(errors.ExpiredTokenError)
		return fmt.Errorf(errors.ExpiredTokenError)
	}

	if validation.MailToken == token {
		err = service.cache.DelCachedValue(validation.UserToken)
		if err != nil {
			log.Printf("error in deleting cached value: %s", err)
			return err
		}

		log.Printf("validation.UserToken: %s", validation.UserToken)
		/* ovaj deo je takodje vezan za pokusaj sa id-em
		userID, err := primitive.ObjectIDFromHex(validation.UserToken)
		user := service.store.GetOneUserByID(userID)

		user.Verified = true*/
		user, err := service.store.GetOneUser(validation.UserToken)
		if user == nil {
			log.Println("user not found")
			return fmt.Errorf("user not found")
		}
		user.Verified = true

		err = service.store.UpdateUserUsername(user)
		if err != nil {
			log.Printf("error in updating user after changing status of verify: %s", err.Error())
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
		log.Println("POST CACHE DATA PROBLEM")
		return err
	}

	err = sendValidationMail(tokenUUID, request.UserMail)
	if err != nil {
		log.Println("SEND VALIDATION MAIL PROBLEM")
		return err
	}

	return nil
}

func (service *AuthService) SendRecoveryPasswordToken(email string) (string, int, error) {

	userServiceEndpoint := fmt.Sprintf("http://%s:%s/mailExist/%s", userServiceHost, userServicePort, email)
	userServiceRequest, _ := http.NewRequest("GET", userServiceEndpoint, nil)
	response, _ := http.DefaultClient.Do(userServiceRequest)
	if response.StatusCode != 200 {
		if response.StatusCode == 404 {
			return "", 404, fmt.Errorf(errors.NotFoundMailError)
		}
	}

	buf := new(strings.Builder)
	_, _ = io.Copy(buf, response.Body)
	userID := buf.String()

	userDetailsEndpoint := fmt.Sprintf("http://%s:%s/%s", userServiceHost, userServicePort, userID)
	userDetailsRequest, _ := http.NewRequest("GET", userDetailsEndpoint, nil)
	userDetailsResponse, _ := http.DefaultClient.Do(userDetailsRequest)

	body, err := ioutil.ReadAll(userDetailsResponse.Body)
	if err != nil {
		return "", 500, err
	}

	responseBodyString := string(body)
	log.Printf("User details response: %s", responseBodyString)

	var userDetails UserDetails
	err = json.Unmarshal(body, &userDetails)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return "", 0, nil
	}

	fmt.Println("Username:", userDetails.Username)

	userUsernameCredentials, err := service.store.GetOneUser(userDetails.Username)
	if err != nil {
		return "", 500, err
	}
	userID = userUsernameCredentials.ID.Hex()

	fmt.Println("Retrieved user ID:", userID)

	recoverUUID, _ := uuid.NewUUID()
	err = sendRecoverPasswordMail(recoverUUID, email)
	if err != nil {
		return "", 500, err
	}

	err = service.cache.PostCacheData(userID, recoverUUID.String())
	if err != nil {
		return "", 500, err
	}

	return userID, 200, nil
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
	message := gomail.NewMessage()
	message.SetHeader("From", smtpEmail)
	message.SetHeader("To", email)
	message.SetHeader("Subject", "Recover password on your Airbnb account")

	bodyString := fmt.Sprintf("Your recover password token is:\n%s", validationToken)
	message.SetBody("text", bodyString)

	client := gomail.NewDialer(smtpServer, smtpServerPort, smtpEmail, smtpPassword)

	if err := client.DialAndSend(message); err != nil {
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
		return fmt.Errorf(errors.InvalidTokenError)
	}

	if request.MailToken != token {
		return fmt.Errorf(errors.InvalidTokenError)
	}

	_ = service.cache.DelCachedValue(request.UserToken)
	return nil
}

func (service *AuthService) RecoverPassword(recoverPassword *domain.RecoverPasswordRequest) error {
	log.Println("Starting password recovery process...")
	if recoverPassword.NewPassword != recoverPassword.RepeatedNew {
		return fmt.Errorf(errors.NotMatchingPasswordsError)
	}

	primitiveID, err := primitive.ObjectIDFromHex(recoverPassword.UserID)
	if err != nil {
		log.Printf("Error converting user ID to ObjectID: %s", err)
		return err
	}
	// Log the user ID
	log.Printf("Recovering password for user ID: %s", primitiveID.Hex())

	credentials := service.store.GetOneUserByID(primitiveID)
	if credentials == nil {
		log.Printf("User not found for ID: %s", primitiveID.Hex())
		return fmt.Errorf("User not found")
	}

	pass := []byte(recoverPassword.NewPassword)
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	credentials.Password = string(hash)

	err = service.store.UpdateUser(credentials)
	if err != nil {
		return err
	}

	return nil
}

func (service *AuthService) ChangePassword(password domain.PasswordChange, token string) (string, int, error) {

	parsedToken := authorization.GetToken(token)
	claims := authorization.GetMapClaims(parsedToken.Bytes())

	username := claims["username"]

	user, err := service.store.GetOneUser(username)
	if err != nil {
		log.Println(err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password.OldPassword))
	if err != nil {
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
			return "baseErr", http.StatusInternalServerError, err
		}

	} else {
		return "newPassErr", http.StatusNotAcceptable, fmt.Errorf("New password does not match confirmation")

	}

	return "OK", http.StatusOK, nil
}

func (service *AuthService) Login(credentials *domain.Credentials) (string, error) {
	user, err := service.store.GetOneUser(credentials.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf(errors.InvalidCredentials)
		}
		return "", fmt.Errorf("Error retrieving user: %v", err)
	}

	if user == nil {
		return "", fmt.Errorf(errors.InvalidCredentials)
	}

	if !user.Verified {
		userServiceEndpoint := fmt.Sprintf("http://%s:%s/%s", userServiceHost, userServicePort, user.ID.Hex())
		userServiceRequest, _ := http.NewRequest("GET", userServiceEndpoint, nil)
		response, _ := http.DefaultClient.Do(userServiceRequest)
		if response.StatusCode != 200 {
			if response.StatusCode == 404 {
				return "", fmt.Errorf("user doesn't exist")
			}
		}

		var userUser domain.User
		err := responseToType(response.Body, &userUser)
		if err != nil {
			return "", err
		}

		verify := domain.ResendVerificationRequest{
			UserToken: user.ID.Hex(),
			UserMail:  userUser.Email,
		}

		err = service.ResendVerificationToken(&verify)
		if err != nil {
			return "", err
		}

		return user.ID.Hex(), fmt.Errorf(errors.NotVerificatedUser)
	}

	passError := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if passError != nil {
		return "not_same", err
	}

	tokenString, err := GenerateJWT(user)

	if err != nil {
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
