package main

import (
	"accommodations_service/data"
	"accommodations_service/handlers"
	"context"
	"errors"
	"github.com/casbin/casbin"
	"github.com/cristalhq/jwt/v4"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
)

func main() {

	port := os.Getenv("ACCOMMODATIONS_SERVICE_PORT")

	timeoutContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	//Initialize the logger we are going to use, with prefix and datetime for every log
	logger := log.New(os.Stdout, "[acc-api] ", log.LstdFlags)
	storeLogger := log.New(os.Stdout, "[acc-store] ", log.LstdFlags)

	// NoSQL: Initialize Product Repository store
	store, err := data.New(timeoutContext, storeLogger)
	if err != nil {
		logger.Fatal(err)
	}
	defer store.DisconnectMongo(timeoutContext)
	store.Ping()

	accommodationHandler := handlers.NewAccommodationHandler(logger, store)

	//Initialize the router and add a middleware for all the requests
	router := mux.NewRouter()
	router.Use(MiddlewareContentTypeSet)

	casbinMiddleware, err := InitializeCasbinMiddleware("./rbac_model.conf", "./policy.csv")
	if err != nil {
		log.Fatal(err)
	}
	router.Use(casbinMiddleware)

	getAccommodation := router.Methods(http.MethodGet).Subrouter()
	getAccommodation.HandleFunc("/", accommodationHandler.GetAll)
	getAllRate := router.Methods(http.MethodGet).Subrouter()
	getAllRate.HandleFunc("/getAllRate", accommodationHandler.GetAllRate)
	getRatesByAccommodation := router.Methods(http.MethodGet).Subrouter()
	getRatesByAccommodation.HandleFunc("/getRatesByAccommodation/{id}", accommodationHandler.GetRatesByAccommodation)
	getRatesByHost := router.Methods(http.MethodGet).Subrouter()
	getRatesByHost.HandleFunc("/getRatesByHost/{id}", accommodationHandler.GetRatesByHost)
	searchAccommodations := router.Methods(http.MethodGet).Subrouter()
	searchAccommodations.HandleFunc("/search", accommodationHandler.SearchAccommodations)
	getAccommodationId := router.Methods(http.MethodGet).Subrouter()
	getAccommodationId.HandleFunc("/{id}", accommodationHandler.GetByID)
	getAccommodationsByOwner := router.Methods(http.MethodGet).Subrouter()
	getAccommodationsByOwner.HandleFunc("/owner/{ownerID}", accommodationHandler.GetAccommodationsByOwner)
	postAccommodation := router.Methods(http.MethodPost).Subrouter()
	postAccommodation.HandleFunc("/", accommodationHandler.CreateAccommodation)
	postAccommodation.Use(accommodationHandler.MiddlewareAccommodationDeserialization)
	postRateForAccommodation := router.Methods(http.MethodPost).Subrouter()
	postRateForAccommodation.HandleFunc("/createRateForAccommodation", accommodationHandler.CreateRateForAccommodation)
	postRateForAccommodation.Use(accommodationHandler.MiddlewareRateDeserialization)
	postRateForHost := router.Methods(http.MethodPost).Subrouter()
	postRateForHost.HandleFunc("/createRateForHost", accommodationHandler.CreateRateForHost)
	postRateForHost.Use(accommodationHandler.MiddlewareRateDeserialization)
	updateRateForHost := router.Methods(http.MethodPatch).Subrouter()
	updateRateForHost.HandleFunc("/updateRate/{rateID}", accommodationHandler.UpdateRateForHost)
	updateRateForHost.Use(accommodationHandler.MiddlewareRateDeserialization)
	deleteAccommodationsByOwner := router.Methods(http.MethodDelete).Subrouter()
	deleteAccommodationsByOwner.HandleFunc("/delete_accommodations/{ownerID}", accommodationHandler.DeleteAccommodationsByOwnerID)
	deleteRateForHost := router.Methods(http.MethodDelete).Subrouter()
	deleteRateForHost.HandleFunc("/deleteRate/{rateID}", accommodationHandler.DeleteRateForHost)

	//Initialize the server
	server := http.Server{
		Addr:         ":" + port,
		Handler:      router,
		IdleTimeout:  120 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}

	logger.Println("Server listening on port", port)

	go func() {
		err := server.ListenAndServe()
		if err != nil {
			logger.Fatal(err)
		}
	}()

	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, os.Interrupt)
	signal.Notify(sigCh, os.Kill)

	sig := <-sigCh
	logger.Println("Received terminate, graceful shutdown", sig)

	if server.Shutdown(timeoutContext) != nil {
		logger.Fatal("Cannot gracefully shutdown...")
	}
	logger.Println("Server stopped")

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

var jwtKey = []byte(os.Getenv("SECRET_KEY"))

var verifier, _ = jwt.NewVerifierHS(jwt.HS256, jwtKey)

func parseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse([]byte(tokenString), verifier)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return token, nil
}

func extractUserType(r *http.Request) (string, error) {
	bearer := r.Header.Get("Authorization")
	if bearer == "" {
		return "Unauthenticated", nil
	}

	bearerToken := strings.Split(bearer, "Bearer ")
	if len(bearerToken) != 2 {
		return "", errors.New("invalid token format")
	}

	tokenString := bearerToken[1]
	token, err := parseToken(tokenString)
	if err != nil {
		return "", err
	}

	claims := extractClaims(token)
	return claims["userType"], nil
}

func extractClaims(token *jwt.Token) map[string]string {
	var claims map[string]string

	err := jwt.ParseClaims(token.Bytes(), verifier, &claims)
	if err != nil {
		log.Println(err)
	}

	return claims
}

func InitializeCasbinMiddleware(modelPath, policyPath string) (func(http.Handler) http.Handler, error) {
	e, err := casbin.NewEnforcerSafe(modelPath, policyPath)
	if err != nil {
		return nil, err
	}

	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			userRole, err := extractUserType(r)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			res, err := e.EnforceSafe(userRole, r.URL.Path, r.Method)
			if err != nil {
				log.Println("Enforce error:", err)
				http.Error(w, "Unauthorized user", http.StatusUnauthorized)
				return
			}

			if res {
				log.Println("Redirect")
				next.ServeHTTP(w, r)
			} else {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		return http.HandlerFunc(fn)
	}, nil
}
