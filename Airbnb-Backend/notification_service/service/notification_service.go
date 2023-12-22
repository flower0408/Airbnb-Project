package application

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sony/gobreaker"
	"gopkg.in/gomail.v2"
	"io/ioutil"
	"log"
	"net/http"
	"notification_service/domain"
	"os"
	"strings"
	"time"
)

var (
	userServiceHost = os.Getenv("USER_SERVICE_HOST")
	userServicePort = os.Getenv("USER_SERVICE_PORT")
	smtpServer      = "smtp.office365.com"
	smtpServerPort  = 587
	smtpEmail       = os.Getenv("SMTP_AUTH_MAIL")
	smtpPassword    = os.Getenv("SMTP_AUTH_PASSWORD")
)

type NotificationService struct {
	store domain.NotificationStore
	cb    *gobreaker.CircuitBreaker
}

func NewNotificationService(store domain.NotificationStore) *NotificationService {
	return &NotificationService{
		store: store,
		cb:    CircuitBreaker("notificationService"),
	}
}

func (service *NotificationService) GetNotificationByHostId(hostId string) ([]*domain.Notification, error) {
	return service.store.GetNotificationsByHostId(hostId)
}

func (service *NotificationService) GetAllNotifications() ([]*domain.Notification, error) {
	return service.store.GetAllNotifications()
}

func (service *NotificationService) CreateNotification(notification *domain.Notification) error {
	notificationInfo := domain.Notification{
		ID:          notification.ID,
		ByGuestId:   notification.ByGuestId,
		ForHostId:   notification.ForHostId,
		Description: notification.Description,
		CreatedAt:   time.Now(),
	}

	_, err := service.store.CreateNotification(&notificationInfo)
	if err != nil {
		return err
	}

	result, breakerErr := service.cb.Execute(func() (interface{}, error) {
		userDetails, err := getUserDetails(notification.ForHostId)
		return userDetails, err
	})

	if breakerErr != nil {
		return breakerErr
	}

	userDetails, ok := result.(*UserDetails)
	if !ok {
		return fmt.Errorf("Internal server error: Unexpected result type")
	}

	log.Printf("User details response: %+v", userDetails)

	email := strings.TrimSpace(userDetails.Email)

	if email == "" {
		return errors.New("Empty email address")
	}

	fmt.Println("Email:", userDetails.Email)

	err = sendValidationMail(notification.Description, email)
	if err != nil {
		return err
	}

	return nil
}

func getUserDetails(userID string) (*UserDetails, error) {
	userDetailsEndpoint := fmt.Sprintf("http://%s:%s/%s", userServiceHost, userServicePort, userID)
	userDetailsResponse, err := http.Get(userDetailsEndpoint)
	if err != nil {
		return nil, fmt.Errorf("UserServiceError: %v", err)
	}
	defer userDetailsResponse.Body.Close()

	body, err := ioutil.ReadAll(userDetailsResponse.Body)
	if err != nil {
		return nil, err
	}

	log.Printf("Raw user details response: %s", body)

	var userDetails UserDetails
	err = json.Unmarshal(body, &userDetails)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return nil, err
	}

	return &userDetails, nil
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

func sendValidationMail(Description, email string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", smtpEmail)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Notification created")

	bodyString := fmt.Sprintf("%s", Description)
	m.SetBody("text", bodyString)

	client := gomail.NewDialer(smtpServer, smtpServerPort, smtpEmail, smtpPassword)

	if err := client.DialAndSend(m); err != nil {
		log.Fatalf("Failed to send verification mail because of: %s", err)
		return err
	}

	return nil
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
