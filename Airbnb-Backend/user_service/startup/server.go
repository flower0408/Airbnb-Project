package startup

import (
	"context"
	"fmt"
	gorillaHandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
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

func (server *Server) initMongoClient() *mongo.Client {
	client, err := store.GetClient(server.config.UserDBHost, server.config.UserDBPort)
	if err != nil {
		log.Fatal(err)
	}
	return client
}

func (server *Server) initUserStore(client *mongo.Client) domain.UserStore {
	store := store.NewUserMongoDBStore(client)

	return store
}

func (server *Server) Start() {
	mongoClient := server.initMongoClient()
	defer func(mongoClient *mongo.Client, ctx context.Context) {
		err := mongoClient.Disconnect(ctx)
		if err != nil {

		}
	}(mongoClient, context.Background())

	userStore := server.initUserStore(mongoClient)
	userService := server.initUserService(userStore)
	userHandler := server.initUserHandler(userService)

	server.start(userHandler)
}

func (server *Server) initUserService(store domain.UserStore) *application.UserService {
	return application.NewUserService(store)
}

func (server *Server) initUserHandler(service *application.UserService) *handlers.UserHandler {
	return handlers.NewUserHandler(service)
}

func (server *Server) start(tweetHandler *handlers.UserHandler) {
	router := mux.NewRouter()
	router.Use(MiddlewareContentTypeSet)
	tweetHandler.Init(router)

	cors := gorillaHandlers.CORS(
		gorillaHandlers.AllowedOrigins([]string{"https://localhost:4200"}),
		gorillaHandlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PATCH", "OPTIONS"}),
		gorillaHandlers.AllowedHeaders([]string{"Authorization, Origin, X-Requested-With, Content-Type, Accept"}))

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", server.config.Port),
		Handler: cors(router),
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

		rw.Header().Set("Content-Security-Policy", "default-src 'self' script-src 'self' 'unsafe-inline' trusted-scripts.com; style-src 'self' 'unsafe-inline' trusted-styles.com; img-src 'self' data:")

		next.ServeHTTP(rw, h)
	})
}
