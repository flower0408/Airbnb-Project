package startup

import (
	"auth_service/domain"
	"auth_service/handlers"
	"auth_service/service"
	"auth_service/startup/config"
	store2 "auth_service/store"
	"context"
	"fmt"
	"github.com/andjelabjekovic/logovi"
	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var logger, loggingMiddleware, writeInfo, writeError, writeRequestInfo, writeRequestError = logovi.LogInit("/logs/logfile.log", "accommodation_service")

type Server struct {
	config *config.Config
}

func NewServer(config *config.Config) *Server {
	return &Server{
		config: config,
	}
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
			log.Printf("Error disconnecting from MongoDB: %v", err)
		}
	}(mongoClient, context.Background())

	redisClient := server.initRedisClient()
	authCache := server.initAuthCache(redisClient)
	authStore := server.initAuthStore(mongoClient)
	authService := server.initAuthService(authStore, authCache)
	authHandler := server.initAuthHandler(authService)

	server.start(authHandler)
}

func (server *Server) initMongoClient(httpClient *http.Client) *mongo.Client {
	client, err := store2.GetClientWithHTTPConfig(server.config.AuthDBHost, server.config.AuthDBPort, httpClient)
	if err != nil {
		log.Fatal(err)
	}
	return client
}

func (server *Server) initRedisClient() *redis.Client {
	client, err := store2.GetRedisClient(server.config.AuthCacheHost, server.config.AuthCachePort)
	if err != nil {
		log.Fatal(err)
	}
	return client
}

func (server *Server) initAuthStore(client *mongo.Client) domain.AuthStore {
	store := store2.NewAuthMongoDBStore(client)
	return store
}

func (server *Server) initAuthCache(client *redis.Client) domain.AuthCache {
	cache := store2.NewAuthRedisCache(client)
	return cache
}

func (server *Server) initAuthService(store domain.AuthStore, cache domain.AuthCache) *application.AuthService {
	return application.NewAuthService(store, cache)
}

func (server *Server) initAuthHandler(service *application.AuthService) *handlers.AuthHandler {
	return handlers.NewAuthHandler(logger, writeError, writeInfo, writeRequestInfo, writeRequestError, service)
}

func (server *Server) start(authHandler *handlers.AuthHandler) {
	router := mux.NewRouter()
	router.Use(MiddlewareContentTypeSet)
	authHandler.Init(router)

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
