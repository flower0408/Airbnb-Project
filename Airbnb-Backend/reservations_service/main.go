package main

import (
	"context"
	gorillaHandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"os/signal"
	"reservations_service/data"
	"reservations_service/handlers"
	"time"
)

func main() {

	port := os.Getenv("RESERVATIONS_SERVICE_PORT")

	timeoutContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	//Initialize the logger we are going to use, with prefix and datetime for every log
	logger := log.New(os.Stdout, "[res-api] ", log.LstdFlags)
	storeLogger := log.New(os.Stdout, "[res-store] ", log.LstdFlags)

	logger2 := log.New(os.Stdout, "[app-api] ", log.LstdFlags)
	storeLogger2 := log.New(os.Stdout, "[app-store] ", log.LstdFlags)

	// NoSQL: Initialize Product Repository store
	store, err := data.NewReservationRepo(storeLogger)
	if err != nil {
		logger.Fatal(err)
	}

	// NoSQL: Initialize Product Repository store
	store2, err := data.NewAppointmentRepo(timeoutContext, storeLogger2)
	if err != nil {
		logger2.Fatal(err)
	}
	defer store.CloseSession()
	defer store2.DisconnectMongo(timeoutContext)
	store.CreateTables()
	store2.Ping()

	reservationHandler := handlers.NewReservationHandler(logger, store)
	appointmentHandler := handlers.NewAppointmentHandler(logger, store2)

	//Initialize the router and add a middleware for all the requests
	router := mux.NewRouter()
	router.Use(reservationHandler.MiddlewareContentTypeSet)

	createReservation := router.Methods(http.MethodPost).Subrouter()
	createReservation.HandleFunc("/reservations", reservationHandler.CreateReservation)
	createReservation.Use(reservationHandler.MiddlewareReservationDeserialization)

	createAppointment := router.Methods(http.MethodPost).Subrouter()
	createAppointment.HandleFunc("/appointments", appointmentHandler.CreateAppointment)
	createAppointment.Use(appointmentHandler.MiddlewareAppointmentDeserialization)

	updateAppointment := router.Methods(http.MethodPatch).Subrouter()
	updateAppointment.HandleFunc("/appointments/{id}", appointmentHandler.UpdateAppointment)
	updateAppointment.Use(appointmentHandler.MiddlewareAppointmentDeserialization)

	createPriceForInterval := router.Methods(http.MethodPatch).Subrouter()
	createPriceForInterval.HandleFunc("/appointments/addPrice/{id}", appointmentHandler.CreatePriceForInterval)
	createPriceForInterval.Use(appointmentHandler.MiddlewarePriceForIntervalDeserialization)

	updatePriceForInterval := router.Methods(http.MethodPatch).Subrouter()
	updatePriceForInterval.HandleFunc("/appointments/editPrice/{id}/{intervalId}", appointmentHandler.UpdatePriceForInterval)
	updatePriceForInterval.Use(appointmentHandler.MiddlewarePriceForIntervalDeserialization)

	cors := gorillaHandlers.CORS(gorillaHandlers.AllowedOrigins([]string{"*"}))

	//Initialize the server
	server := http.Server{
		Addr:         ":" + port,
		Handler:      cors(router),
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
