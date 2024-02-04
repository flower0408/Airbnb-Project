package startup

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"
	"log"
	"net/http"
	"os"
	"os/signal"
	"recommendations_service/domain"
	"recommendations_service/handlers"
	application "recommendations_service/service"
	"recommendations_service/startup/config"
	"recommendations_service/store"
	"syscall"
	"time"
)

type Server struct {
	config *config.Config
}

func NewServer(config *config.Config) *Server {
	return &Server{
		config: config,
	}
}

func (server *Server) initNeo4JDriver(httpClient *http.Client) *neo4j.DriverWithContext {
	driver, err := store.GetClient(server.config.RecommendationDBHost, server.config.RecommendationDBPort,
		server.config.RecommendationDBUser, server.config.RecommendationDBPass, httpClient)
	if err != nil {
		log.Fatal(err)
	}
	return driver
}

func (server *Server) initRecommendationStore(driver *neo4j.DriverWithContext, tracer trace.Tracer) domain.RecommendationStore {
	store := store.NewRecommendationNeo4JStore(driver, tracer)

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

	cfg := config.NewConfig()

	ctx := context.Background()
	exp, err := newExporter(cfg.JaegerAddress)
	if err != nil {
		log.Fatalf("Failed to Initialize Exporter: %v", err)
	}

	tp := newTraceProvider(exp)
	defer func() { _ = tp.Shutdown(ctx) }()
	otel.SetTracerProvider(tp)
	tracer := tp.Tracer("recommendations_service")

	neo4jDriver := server.initNeo4JDriver(httpClient)
	recommendationStore := server.initRecommendationStore(neo4jDriver, tracer)
	recommendationService := server.initRecommendationService(recommendationStore, tracer)
	recommendationHandler := server.initRecommendationHandler(recommendationService, tracer)

	server.start(recommendationHandler)
}

func (server *Server) initRecommendationService(store domain.RecommendationStore, tracer trace.Tracer) *application.RecommendationService {
	return application.NewRecommendationService(store, tracer)
}

func (server *Server) initRecommendationHandler(service *application.RecommendationService, tracer trace.Tracer) *handlers.RecommendationHandler {
	return handlers.NewRecommendationHandler(service, tracer)
}

func (server *Server) start(recommendedHandler *handlers.RecommendationHandler) {
	router := mux.NewRouter()
	router.Use(MiddlewareContentTypeSet)
	recommendedHandler.Init(router)

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
			semconv.ServiceNameKey.String("recommendations_service"),
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
