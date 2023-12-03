package main

import (
	"context"
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
	router.Use(MiddlewareContentTypeSet)

	createReservation := router.Methods(http.MethodPost).Subrouter()
	createReservation.HandleFunc("/reservations", reservationHandler.CreateReservation)
	createReservation.Use(reservationHandler.MiddlewareReservationDeserialization)

	checkReservation := router.Methods(http.MethodPost).Subrouter()
	checkReservation.HandleFunc("/check", reservationHandler.CheckReservation)
	//checkReservation.Use(reservationHandler.MiddlewareReservationDeserialization)

	getReservationByUser := router.Methods(http.MethodGet).Subrouter()
	getReservationByUser.HandleFunc("/reservationsByUser/{id}", reservationHandler.GetReservationByUser)
	//getAllReservation.Use(reservationHandler.MiddlewareReservationDeserialization)

	getReservationByAccommodation := router.Methods(http.MethodGet).Subrouter()
	getReservationByAccommodation.HandleFunc("/reservationsByAccommodation/{id}", reservationHandler.GetReservationByAccommodation)
	//getAllReservation.Use(reservationHandler.MiddlewareReservationDeserialization)

	createAppointment := router.Methods(http.MethodPost).Subrouter()
	createAppointment.HandleFunc("/appointments", appointmentHandler.CreateAppointment)
	createAppointment.Use(appointmentHandler.MiddlewareAppointmentDeserialization)

	getAllAppointment := router.Methods(http.MethodGet).Subrouter()
	getAllAppointment.HandleFunc("/appointments", appointmentHandler.GetAllAppointment)
	//getAllAppointment.Use(appointmentHandler.MiddlewareAppointmentDeserialization)

	getAppointmentByAccommodation := router.Methods(http.MethodGet).Subrouter()
	getAppointmentByAccommodation.HandleFunc("/appointmentsByAccommodation/{id}", appointmentHandler.GetAppointmentsByAccommodation)
	//getAllAppointment.Use(appointmentHandler.MiddlewareAppointmentDeserialization)

	updateAppointment := router.Methods(http.MethodPatch).Subrouter()
	updateAppointment.HandleFunc("/appointments/{id}", appointmentHandler.UpdateAppointment)
	updateAppointment.Use(appointmentHandler.MiddlewareAppointmentDeserialization)

	updatePrice := router.Methods(http.MethodPatch).Subrouter()
	updatePrice.HandleFunc("/appointments/editPrice/{id}", appointmentHandler.UpdatePrice)
	updatePrice.Use(appointmentHandler.MiddlewareAppointmentDeserialization)

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

		rw.Header().Set("Content-Security-Policy", "script-src 'self' https://cdn.jsdelivr.net https://www.google.com https://www.gstatic.com 'unsafe-inline' 'unsafe-eval'; style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com 'unsafe-inline'; font-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data: https://i.ibb.co;")

		next.ServeHTTP(rw, h)
	})
}
