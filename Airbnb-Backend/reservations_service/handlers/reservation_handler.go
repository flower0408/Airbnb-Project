package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"reservations_service/data"
	"time"
)

type KeyProduct struct{}

type ReservationHandler struct {
	logger          *log.Logger
	reservationRepo *data.ReservationRepo
}

func NewReservationHandler(l *log.Logger, r *data.ReservationRepo) *ReservationHandler {
	return &ReservationHandler{l, r}
}

// cassandra
func (s *ReservationHandler) CreateReservation(rw http.ResponseWriter, h *http.Request) {
	reservation := h.Context().Value(KeyProduct{}).(*data.Reservation)
	err := s.reservationRepo.InsertReservation(reservation)
	if err != nil {
		s.logger.Print("Database exception: ", err)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (s *ReservationHandler) GetReservationByUser(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	id := vars["id"]

	reservationByUser, err := s.reservationRepo.GetReservationByUser(id)
	if err != nil {
		s.logger.Print("Database exception: ", err)
	}

	if reservationByUser == nil {
		return
	}

	err = reservationByUser.ToJSON(rw)
	if err != nil {
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		s.logger.Fatal("Unable to convert to json :", err)
		return
	}
}

func (s *ReservationHandler) GetReservationByAccommodation(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	id := vars["id"]

	reservationByUser, err := s.reservationRepo.GetReservationByAccommodation(id)
	if err != nil {
		s.logger.Print("Database exception: ", err)
	}

	if reservationByUser == nil {
		return
	}

	err = reservationByUser.ToJSON(rw)
	if err != nil {
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		s.logger.Fatal("Unable to convert to json :", err)
		return
	}
}

func (s *ReservationHandler) CheckReservation(rw http.ResponseWriter, h *http.Request) {
	var requestBody struct {
		AccommodationID string   `json:"accommodationId"`
		Available       []string `json:"available"`
	}

	err := json.NewDecoder(h.Body).Decode(&requestBody)
	if err != nil {
		http.Error(rw, "Unable to decode JSON", http.StatusBadRequest)
		s.logger.Println("Error decoding JSON:", err)
		return
	}

	// Pretvori stringove u time.Time
	var available []time.Time
	for _, t := range requestBody.Available {
		parsedTime, err := time.Parse(time.RFC3339, t)
		if err != nil {
			http.Error(rw, "Invalid time format in JSON", http.StatusBadRequest)
			s.logger.Println("Error parsing time:", err)
			return
		}
		available = append(available, parsedTime)
	}
	fmt.Println(available, "Available check reservation")

	exists, err := s.reservationRepo.ReservationExistsForAppointment(requestBody.AccommodationID, available)
	if err != nil {
		http.Error(rw, "Error checking reservation", http.StatusInternalServerError)
		s.logger.Println("Error checking reservation:", err)
		return
	}

	if exists {
		rw.WriteHeader(http.StatusBadRequest)
	} else {
		rw.WriteHeader(http.StatusOK)
	}
}

func (s *ReservationHandler) MiddlewareReservationDeserialization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, h *http.Request) {
		reservations := &data.Reservation{}
		err := reservations.FromJSON(h.Body)
		if err != nil {
			http.Error(rw, "Unable to decode json", http.StatusBadRequest)
			s.logger.Fatal(err)
			return
		}
		ctx := context.WithValue(h.Context(), KeyProduct{}, reservations)
		h = h.WithContext(ctx)
		next.ServeHTTP(rw, h)
	})
}
