package application

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/sony/gobreaker"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
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
	store  domain.NotificationStore
	cb     *gobreaker.CircuitBreaker
	tracer trace.Tracer
	logger *logrus.Logger
}

func NewNotificationService(store domain.NotificationStore, tracer trace.Tracer, logger *logrus.Logger) *NotificationService {
	return &NotificationService{
		store:  store,
		cb:     CircuitBreaker("notificationService"),
		tracer: tracer,
		logger: logger,
	}
}

func (service *NotificationService) GetNotificationByHostId(ctx context.Context, hostId string) ([]*domain.Notification, error) {
	ctx, span := service.tracer.Start(ctx, "NotificationService.GetNotificationByHostId")
	defer span.End()

	service.logger.Infoln("NotificationService.GetNotificationByHostId : GetNotificationByHostId service reached")

	return service.store.GetNotificationsByHostId(ctx, hostId)
}

func (service *NotificationService) GetAllNotifications(ctx context.Context) ([]*domain.Notification, error) {
	ctx, span := service.tracer.Start(ctx, "NotificationService.GetAllNotifications")
	defer span.End()

	service.logger.Infoln("NotificationService.GetNotificationByHostId : GetNotificationByHostId service reached")

	return service.store.GetAllNotifications(ctx)
}

func (service *NotificationService) CreateNotification(ctx context.Context, notification *domain.Notification, token string) error {
	ctx, span := service.tracer.Start(ctx, "NotificationService.CreateNotification")
	defer span.End()

	service.logger.Infoln("NotificationService.CreateNotification : CreateNotification service reached")

	notificationInfo := domain.Notification{
		ID:          notification.ID,
		ByGuestId:   notification.ByGuestId,
		ForHostId:   notification.ForHostId,
		Description: notification.Description,
		CreatedAt:   time.Now(),
	}

	_, err := service.store.CreateNotification(ctx, &notificationInfo)
	if err != nil {
		service.logger.Errorln("NotificationService.CreateNotification : Error creating notification")
		span.SetStatus(codes.Error, "Error creating notification")
		return err
	}

	result, breakerErr := service.cb.Execute(func() (interface{}, error) {
		userDetails, err := service.getUserDetails(ctx, notification.ForHostId, token)
		return userDetails, err
	})

	if breakerErr != nil {
		service.logger.Errorln("NotificationService.CreateNotification : Breaker service error")
		span.SetStatus(codes.Error, "Breaker service error")
		return breakerErr
	}

	userDetails, ok := result.(*UserDetails)
	if !ok {
		service.logger.Errorln("NotificationService.CreateNotification : Internal server error: Unexpected result type")
		return fmt.Errorf("Internal server error: Unexpected result type")
	}

	log.Printf("User details response: %+v", userDetails)

	email := strings.TrimSpace(userDetails.Email)

	if email == "" {
		service.logger.Errorln("NotificationService.CreateNotification : Empty email address")
		return errors.New("Empty email address")
	}

	fmt.Println("Email:", userDetails.Email)

	err = service.sendValidationMail(ctx, notification.Description, email)
	if err != nil {
		service.logger.Errorln("NotificationService.CreateNotification : Error sending mail")
		span.SetStatus(codes.Error, "Error sending mail")
		return err
	}

	service.logger.Infoln("NotificationService.CreateNotification : CreateNotification service finished")
	return nil
}

func (service *NotificationService) getUserDetails(ctx context.Context, userID string, token string) (*UserDetails, error) {
	ctx, span := service.tracer.Start(ctx, "NotificationService.getUserDetails")
	defer span.End()

	service.logger.Infoln("NotificationService.getUserDetails : getUserDetails service reached")

	userDetailsEndpoint := fmt.Sprintf("https://%s:%s/%s", userServiceHost, userServicePort, userID)
	userDetailsResponse, err := service.HTTPSRequest(ctx, token, userDetailsEndpoint, "GET")
	if err != nil {
		service.logger.Errorln("NotificationService.getUserDetails : User Service Error")
		span.SetStatus(codes.Error, "UserServiceError")
		return nil, fmt.Errorf("UserServiceError: %v", err)
	}
	defer userDetailsResponse.Body.Close()

	body, err := ioutil.ReadAll(userDetailsResponse.Body)
	if err != nil {
		service.logger.Errorln("NotificationService.getUserDetails : Error reading user details response body")
		span.SetStatus(codes.Error, "Error reading user details response body")
		return nil, err
	}

	log.Printf("Raw user details response: %s", body)

	var userDetails UserDetails
	err = json.Unmarshal(body, &userDetails)
	if err != nil {
		service.logger.Errorln("NotificationService.getUserDetails : Error unmarshalling JSON")
		span.SetStatus(codes.Error, "Error unmarshalling JSON")
		fmt.Println("Error unmarshalling JSON:", err)
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

func (service *NotificationService) sendValidationMail(ctx context.Context, Description, email string) error {
	ctx, span := service.tracer.Start(ctx, "NotificationService.sendValidationMail")
	defer span.End()

	service.logger.Infoln("NotificationService.sendValidationMail : sendValidationMail service reached")

	m := gomail.NewMessage()
	m.SetHeader("From", smtpEmail)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Notification created")

	bodyString := fmt.Sprintf("%s", Description)
	m.SetBody("text", bodyString)

	client := gomail.NewDialer(smtpServer, smtpServerPort, smtpEmail, smtpPassword)

	if err := client.DialAndSend(m); err != nil {
		service.logger.Errorln("NotificationService.sendValidationMail : Failed to send verification mail")
		span.SetStatus(codes.Error, "Failed to send verification mail")
		log.Fatalf("Failed to send verification mail because of: %s", err)
		return err
	}

	service.logger.Infoln("NotificationService.sendValidationMail : sendValidationMail service finished")
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

func (service *NotificationService) HTTPSRequest(ctx context.Context, token string, url string, method string) (*http.Response, error) {
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
