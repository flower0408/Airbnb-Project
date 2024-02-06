package startup

import (
	"context"
	"fmt"
	"github.com/andjelabjekovic/logovi"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
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

func NewServer(config *config.Config) *Server {
	return &Server{
		config: config,
	}
}

func (server *Server) initMongoClient() *mongo.Client {
	client, err := store.GetClient(server.config.NotificationDBHost, server.config.NotificationDBPort)
	if err != nil {
		log.Fatal(err)
	}
	return client
}

func (server *Server) initNotificationStore(client *mongo.Client) domain.NotificationStore {
	store := store.NewNotificationMongoDBStore(client)

	return store
}

func (server *Server) Start() {
	mongoClient := server.initMongoClient()
	defer func(mongoClient *mongo.Client, ctx context.Context) {
		err := mongoClient.Disconnect(ctx)
		if err != nil {

		}
	}(mongoClient, context.Background())

	notificationStore := server.initNotificationStore(mongoClient)
	notificationService := server.initNotificationService(notificationStore)
	notificationHandler := server.initNotificationHandler(notificationService)

	server.start(notificationHandler)
}

func (server *Server) initNotificationService(store domain.NotificationStore) *application.NotificationService {
	return application.NewNotificationService(store)
}

func (server *Server) initNotificationHandler(service *application.NotificationService) *handlers.NotificationHandler {
	return handlers.NewNotificationHandler(service)
}

func (server *Server) start(notificationHandler *handlers.NotificationHandler) {
	router := mux.NewRouter()
	router.Use(MiddlewareContentTypeSet)
	notificationHandler.Init(router)

	_, loggingMiddleware, _, _, _, _ := logovi.LogInit("/logs/logfile.log", "notification_service")
	router.Use(loggingMiddleware)

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
