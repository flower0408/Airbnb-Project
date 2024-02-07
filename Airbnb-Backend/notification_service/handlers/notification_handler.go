package handlers

import (
	"encoding/json"
	"github.com/casbin/casbin"
	"github.com/cristalhq/jwt/v4"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"net/http"
	"notification_service/casbinAuthorization"
	"notification_service/domain"
	application "notification_service/service"
	"os"
	"time"
)

var (
	jwtKey      = []byte(os.Getenv("SECRET_KEY"))
	verifier, _ = jwt.NewVerifierHS(jwt.HS256, jwtKey)
)

type NotificationHandler struct {
	logger            *log.Logger
	service           *application.NotificationService
	writeError        func(msg string)
	writeInfo         func(msg string)
	writeRequestError func(r *http.Request, msg string)
	writeRequestInfo  func(r *http.Request, msg string)
}

func NewNotificationHandler(l *log.Logger, e func(msg string), i func(msg string), re func(r *http.Request, msg string), ri func(r *http.Request, msg string), service *application.NotificationService) *NotificationHandler {
	return &NotificationHandler{
		logger:            l,
		service:           service,
		writeError:        e,
		writeInfo:         i,
		writeRequestError: re,
		writeRequestInfo:  ri,
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
	log.Fatal(http.ListenAndServe(":8005", casbinAuthorization.CasbinMiddleware(CasbinMiddleware1)(router)))
}

type ValidationError struct {
	Message string `json:"message"`
}

func (handler *NotificationHandler) CreateNotification(writer http.ResponseWriter, req *http.Request) {
	var notification domain.Notification
	err := json.NewDecoder(req.Body).Decode(&notification)
	if err != nil {
		handler.writeRequestError(req, "Failed to decode the request")
		log.Println(err)
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	notification.CreatedAt = time.Now()

	err = handler.service.CreateNotification(&notification)
	if err != nil {
		if err.Error() == "Database error" {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		} else {
			http.Error(writer, err.Error(), http.StatusBadRequest)
		}
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (handler *NotificationHandler) GetAllNotifications(writer http.ResponseWriter, req *http.Request) {
	users, err := handler.service.GetAllNotifications()
	if err != nil {
		handler.writeRequestError(req, "Failed to get all notifications")
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	jsonResponse(users, writer)
}

func (handler *NotificationHandler) GetNotificationByHostId(writer http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id, ok := vars["id"]
	if !ok {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	notification, err := handler.service.GetNotificationByHostId(id)
	if err != nil {
		handler.writeRequestError(req, "Failed to get notification by host ID")
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
