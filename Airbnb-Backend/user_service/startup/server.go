package startup

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
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
	"os"
	"os/signal"
	"syscall"
	"time"
	"user_service/domain"
	"user_service/handlers"
	"user_service/service"
	"user_service/startup/config"
	"user_service/store"
)

type Server struct {
	config *config.Config
}

func NewServer(config *config.Config) *Server {
	return &Server{
		config: config,
	}
}

func (server *Server) initMongoClient(httpClient *http.Client) *mongo.Client {
	client, err := store.GetClientWithHTTPConfig(server.config.UserDBHost, server.config.UserDBPort, httpClient)
	if err != nil {
		log.Fatal(err)
	}
	return client
}

func (server *Server) initUserStore(client *mongo.Client, tracer trace.Tracer) domain.UserStore {
	store := store.NewUserMongoDBStore(client, tracer)

	return store
}

func (server *Server) Start() {

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

	userStore := server.initUserStore(mongoClient, tracer)
	userService := server.initUserService(userStore, tracer)
	userHandler := server.initUserHandler(userService, tracer)

	server.start(userHandler)
}

func (server *Server) initUserService(store domain.UserStore, tracer trace.Tracer) *application.UserService {
	return application.NewUserService(store, tracer)
}

func (server *Server) initUserHandler(service *application.UserService, tracer trace.Tracer) *handlers.UserHandler {
	return handlers.NewUserHandler(service, tracer)
}

func (server *Server) start(tweetHandler *handlers.UserHandler) {
	router := mux.NewRouter()
	router.Use(MiddlewareContentTypeSet)
	tweetHandler.Init(router)

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
			semconv.ServiceNameKey.String("user_service"),
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

		rw.Header().Add("Content-Type", "application/json")
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("X-Frame-Options", "DENY")

		rw.Header().Set("Content-Security-Policy", "script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net https://www.google.com https://www.gstatic.com 'unsafe-inline' 'unsafe-eval'; style-src 'self' https://code.jquery.com https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com 'unsafe-inline'; font-src 'self' https://code.jquery.com https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data: https://code.jquery.com https://i.ibb.co;")

		next.ServeHTTP(rw, h)
	})
}
