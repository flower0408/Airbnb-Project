package startup

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"
	"log"
	"net/http"
	"notification_service/domain"
	"notification_service/handlers"
	application "notification_service/service"
	"notification_service/startup/config"
	"notification_service/store"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Server struct {
	config *config.Config
}

var Logger = logrus.New()

const (
	LogFilePath = "/app/logs/notification.log"
)

type CustomFormatter struct{}

func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	entry.Data["id"] = generateUniqueID()

	msg := fmt.Sprintf("[%s] [%s] [%s] %s\n",
		entry.Time.Format("2006-01-02T15:04:05Z07:00"),
		entry.Level,
		entry.Data["id"],
		entry.Message,
	)

	return []byte(msg), nil
}

func generateUniqueID() string {
	return fmt.Sprintf("ID-%d", time.Now().UnixNano())
}

func initLogger() {
	writer, err := rotatelogs.New(
		LogFilePath+"_%Y%m%d%H%M",
		rotatelogs.WithRotationTime(3*time.Minute), // Rotate logs every 15 minutes
	)
	if err != nil {
		Logger.Fatalf("Failed to create rotatelogs hook: %v", err)
	}
	Logger.SetOutput(writer)

	Logger.SetFormatter(&CustomFormatter{})
}

func NewServer(config *config.Config) *Server {
	return &Server{
		config: config,
	}
}

func (server *Server) initMongoClient(httpClient *http.Client) *mongo.Client {
	client, err := store.GetClientWithHTTPConfig(server.config.NotificationDBHost, server.config.NotificationDBPort, httpClient)
	if err != nil {
		log.Fatal(err)
	}
	return client
}

func (server *Server) initNotificationStore(client *mongo.Client, tracer trace.Tracer, logger *logrus.Logger) domain.NotificationStore {
	store := store.NewNotificationMongoDBStore(client, tracer, logger)

	return store
}

func (server *Server) Start() {

	initLogger()

	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			MaxConnsPerHost:     10,
		},
	}

	mongoClient := server.initMongoClient(httpClient)
	defer func(mongoClient *mongo.Client, ctx context.Context) {
		err := mongoClient.Disconnect(ctx)
		if err != nil {

		}
	}(mongoClient, context.Background())

	cfg := config.NewConfig()

	ctx := context.Background()
	exp, err := newExporter(cfg.JaegerAddress)
	if err != nil {
		log.Fatalf("Failed to Initialize Exporter: %v", err)
	}

	tp := newTraceProvider(exp)
	defer func() { _ = tp.Shutdown(ctx) }()
	otel.SetTracerProvider(tp)
	tracer := tp.Tracer("user_service")
	otel.SetTextMapPropagator(propagation.TraceContext{})

	notificationStore := server.initNotificationStore(mongoClient, tracer, Logger)
	notificationService := server.initNotificationService(notificationStore, tracer, Logger)
	notificationHandler := server.initNotificationHandler(notificationService, tracer, Logger)

	server.start(notificationHandler)
}

func (server *Server) initNotificationService(store domain.NotificationStore, tracer trace.Tracer, logger *logrus.Logger) *application.NotificationService {
	return application.NewNotificationService(store, tracer, logger)
}

func (server *Server) initNotificationHandler(service *application.NotificationService, tracer trace.Tracer, logger *logrus.Logger) *handlers.NotificationHandler {
	return handlers.NewNotificationHandler(service, tracer, logger)
}

func (server *Server) start(notificationHandler *handlers.NotificationHandler) {
	router := mux.NewRouter()
	router.Use(MiddlewareContentTypeSet)
	notificationHandler.Init(router)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", server.config.Port),
		Handler: router,
	}

	wait := time.Second * 15
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)

	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	<-c

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Error Shutting Down Server %s", err)
	}
	log.Println("Server Gracefully Stopped")
}

func newExporter(address string) (*jaeger.Exporter, error) {
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(address)))
	if err != nil {
		return nil, err
	}
	return exp, nil
}

func newTraceProvider(exp sdktrace.SpanExporter) *sdktrace.TracerProvider {
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("notification_service"),
		),
	)

	if err != nil {
		panic(err)
	}

	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(r),
	)
}

func MiddlewareContentTypeSet(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, h *http.Request) {
		//s.logger.Println("Method [", h.Method, "] - Hit path :", h.URL.Path)

		rw.Header().Add("Content-Type", "application/json")
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("X-Frame-Options", "DENY")

		rw.Header().Set("Content-Security-Policy", "script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net https://www.google.com https://www.gstatic.com 'unsafe-inline' 'unsafe-eval'; style-src 'self' https://code.jquery.com https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com 'unsafe-inline'; font-src 'self' https://code.jquery.com https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data: https://code.jquery.com https://i.ibb.co;")

		next.ServeHTTP(rw, h)
	})
}
