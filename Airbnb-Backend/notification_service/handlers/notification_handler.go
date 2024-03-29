package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/casbin/casbin"
	"github.com/cristalhq/jwt/v4"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"log"
	"net/http"
	"notification_service/casbinAuthorization"
	"notification_service/domain"
	application "notification_service/service"
	"os"
	"strings"
	"time"
)

var (
	jwtKey      = []byte(os.Getenv("SECRET_KEY"))
	verifier, _ = jwt.NewVerifierHS(jwt.HS256, jwtKey)
)

type NotificationHandler struct {
	service *application.NotificationService
	tracer  trace.Tracer
}

func NewNotificationHandler(service *application.NotificationService, tracer trace.Tracer) *NotificationHandler {
	return &NotificationHandler{
		service: service,
		tracer:  tracer,
	}
}

func (handler *NotificationHandler) Init(router *mux.Router) {

	CasbinMiddleware1, err := casbin.NewEnforcerSafe("./rbac_model.conf", "./policy.csv")

	log.Println("notification service successful init of enforcer")
	if err != nil {
		log.Fatal(err)
	}

	router.Use(ExtractTraceInfoMiddleware)
	router.HandleFunc("/{id}", handler.GetNotificationByHostId).Methods("GET")
	router.HandleFunc("/", handler.GetAllNotifications).Methods("GET")
	router.HandleFunc("/", handler.CreateNotification).Methods("POST")

	http.Handle("/", router)
	log.Fatal(http.ListenAndServeTLS(":8005", "notification_service-cert.pem", "notification_service-key.pem", casbinAuthorization.CasbinMiddleware(CasbinMiddleware1)(router)))
}

type ValidationError struct {
	Message string `json:"message"`
}

func (handler *NotificationHandler) CreateNotification(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "NotificationHandler.CreateNotification")
	defer span.End()

	var notification domain.Notification
	err := json.NewDecoder(req.Body).Decode(&notification)
	if err != nil {
		log.Println(err)
		span.SetStatus(codes.Error, "Status bad request")
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	notification.CreatedAt = time.Now()

	tokenString, err := extractTokenFromHeader(req)
	if err != nil {
		span.SetStatus(codes.Error, "No token found")
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("No token found"))
		return
	}

	err = handler.service.CreateNotification(ctx, &notification, tokenString)
	if err != nil {
		if err.Error() == "Database error" {
			span.SetStatus(codes.Error, "Internal server error")
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		} else {
			span.SetStatus(codes.Error, "Status bad request")
			http.Error(writer, err.Error(), http.StatusBadRequest)
		}
		return
	}

	writer.WriteHeader(http.StatusOK)
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

func (handler *NotificationHandler) GetAllNotifications(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "NotificationHandler.GetAllNotifications")
	defer span.End()

	users, err := handler.service.GetAllNotifications(ctx)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting all notifications")
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	jsonResponse(users, writer)
}

func (handler *NotificationHandler) GetNotificationByHostId(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "NotificationHandler.GetNotificationByHostId")
	defer span.End()

	vars := mux.Vars(req)
	id, ok := vars["id"]
	if !ok {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	notification, err := handler.service.GetNotificationByHostId(ctx, id)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting notifications for host")
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	jsonResponse(notification, writer)
}

func ExtractTraceInfoMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
