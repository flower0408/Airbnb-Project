package main

import (
	"context"
	"errors"
	"github.com/casbin/casbin"
	"github.com/cristalhq/jwt/v4"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"log"
	"net/http"
	"os"
	"os/signal"
	"reservations_service/data"
	"reservations_service/handlers"
	"strings"
	"time"
)

var (
	JaegerAddress = os.Getenv("JAEGER_ADDRESS")
)

func main() {

	port := os.Getenv("RESERVATIONS_SERVICE_PORT")

	timeoutContext, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	exp, err := newExporter(JaegerAddress)
	if err != nil {
		log.Fatalf("failed to initialize exporter: %v", err)
	}
	// Create a new tracer provider with a batch span processor and the given exporter.
	tp := newTraceProvider(exp)
	// Handle shutdown properly so nothing leaks.
	defer func() { _ = tp.Shutdown(timeoutContext) }()
	otel.SetTracerProvider(tp)
	// Finally, set the tracer that can be used for this package.
	tracer := tp.Tracer("reservations_service")
	otel.SetTextMapPropagator(propagation.TraceContext{})

	//Initialize the logger we are going to use, with prefix and datetime for every log
	logger := log.New(os.Stdout, "[res-api] ", log.LstdFlags)
	storeLogger := log.New(os.Stdout, "[res-store] ", log.LstdFlags)

	logger2 := log.New(os.Stdout, "[app-api] ", log.LstdFlags)
	storeLogger2 := log.New(os.Stdout, "[app-store] ", log.LstdFlags)

	// NoSQL: Initialize Product Repository store
	store, err := data.NewReservationRepo(tracer, storeLogger)
	if err != nil {
		logger.Fatal(err)
	}

	// NoSQL: Initialize Product Repository store
	store2, err := data.NewAppointmentRepo(timeoutContext, storeLogger2, tracer)
	if err != nil {
		logger2.Fatal(err)
	}
	defer store.CloseSession()
	defer store2.DisconnectMongo(timeoutContext)
	store.CreateTables()
	store2.Ping()

	reservationHandler := handlers.NewReservationHandler(logger, store, tracer)
	appointmentHandler := handlers.NewAppointmentHandler(logger, store2, tracer)

	//Initialize the router and add a middleware for all the requests
	router := mux.NewRouter()
	router.Use(handlers.ExtractTraceInfoMiddleware)
	router.Use(MiddlewareContentTypeSet)

	casbinMiddleware, err := InitializeCasbinMiddleware("./rbac_model.conf", "./policy.csv")
	if err != nil {
		log.Fatal(err)
	}
	router.Use(casbinMiddleware)

	getAppointmentByAccommodation := router.Methods(http.MethodGet).Subrouter()
	getAppointmentByAccommodation.HandleFunc("/appointmentsByAccommodation/{id}", appointmentHandler.GetAppointmentsByAccommodation)
	//getAllAppointment.Use(appointmentHandler.MiddlewareAppointmentDeserialization)

	getAppointmentsByDate := router.Methods(http.MethodGet).Subrouter()
	getAppointmentsByDate.HandleFunc("/appointmentsByDate/", appointmentHandler.GetAppointmentsByDate)

	createAppointment := router.Methods(http.MethodPost).Subrouter()
	createAppointment.HandleFunc("/appointments", appointmentHandler.CreateAppointment)
	createAppointment.Use(appointmentHandler.MiddlewareAppointmentDeserialization)

	getAllAppointment := router.Methods(http.MethodGet).Subrouter()
	getAllAppointment.HandleFunc("/appointments", appointmentHandler.GetAllAppointment)
	//getAllAppointment.Use(appointmentHandler.MiddlewareAppointmentDeserialization)

	createReservation := router.Methods(http.MethodPost).Subrouter()
	createReservation.HandleFunc("/reservations", reservationHandler.CreateReservation)
	createReservation.Use(reservationHandler.MiddlewareReservationDeserialization)

	/*getReservationById := router.Methods(http.MethodGet).Subrouter()
	getReservationById.HandleFunc("/reservationById/{id}", reservationHandler.GetReservationById)*/

	getReservationByAccommodation := router.Methods(http.MethodGet).Subrouter()
	getReservationByAccommodation.HandleFunc("/reservationsByAccommodation/{id}", reservationHandler.GetReservationByAccommodation)
	//getAllReservation.Use(reservationHandler.MiddlewareReservationDeserialization)

	checkReservation := router.Methods(http.MethodPost).Subrouter()
	checkReservation.HandleFunc("/check", reservationHandler.CheckReservation)
	//checkReservation.Use(reservationHandler.MiddlewareReservationDeserialization)

	updateAppointment := router.Methods(http.MethodPatch).Subrouter()
	updateAppointment.HandleFunc("/appointments/{id}", appointmentHandler.UpdateAppointment)
	updateAppointment.Use(appointmentHandler.MiddlewareAppointmentDeserialization)

	checkReservationsForHost := router.Methods(http.MethodGet).Subrouter()
	checkReservationsForHost.HandleFunc("/reservationsByHost/{id}", reservationHandler.CheckHostReservations)

	getReservationByUser := router.Methods(http.MethodGet).Subrouter()
	getReservationByUser.HandleFunc("/reservationsByUser", reservationHandler.GetReservationByUser)
	//getAllReservation.Use(reservationHandler.MiddlewareReservationDeserialization)

	checkUserPastReservations := router.Methods(http.MethodGet).Subrouter()
	checkUserPastReservations.HandleFunc("/checkUserPastReservations/{id}/{hostId}", reservationHandler.CheckUserPastReservations)

	checkUserPastReservationsInAccommodation := router.Methods(http.MethodGet).Subrouter()
	checkUserPastReservationsInAccommodation.HandleFunc("/checkUserPastReservationsInAccommodation/{id}/{accommodationId}", reservationHandler.CheckUserPastReservationsInAccommodation)

	cancelReservation := router.Methods(http.MethodDelete).Subrouter()
	cancelReservation.HandleFunc("/cancelReservation/{id}", reservationHandler.CancelReservation)
	//cancelReservation.Use(reservationHandler.MiddlewareReservationDeserialization)

	deleteAppointment := router.Methods(http.MethodDelete).Subrouter()
	deleteAppointment.HandleFunc("/deleteAppointments/{id}", appointmentHandler.DeleteAppointmentsByAccommodationIDs)

	cancellationRate := router.Methods(http.MethodGet).Subrouter()
	cancellationRate.HandleFunc("/cancellationRate/{id}", reservationHandler.CheckCancellationRateBelowThreshold)

	numOfReservations := router.Methods(http.MethodGet).Subrouter()
	numOfReservations.HandleFunc("/numOfReservations/{id}", reservationHandler.HasEnoughCompletedReservations)

	durationOfReservations := router.Methods(http.MethodGet).Subrouter()
	durationOfReservations.HandleFunc("/durationOfReservations/{id}", reservationHandler.CheckReservationsMoreThan50Days)

	//Initialize the server
	server := http.Server{
		Addr:         ":" + port,
		Handler:      router,
		IdleTimeout:  120 * time.Second,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
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
	e.EnableLog(true)

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

func newExporter(address string) (*jaeger.Exporter, error) {
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(address)))
	if err != nil {
		return nil, err
	}
	return exp, nil
}

func newTraceProvider(exp sdktrace.SpanExporter) *sdktrace.TracerProvider {
	// Ensure default SDK resources and the required service name are set.
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("reservations_service"),
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
