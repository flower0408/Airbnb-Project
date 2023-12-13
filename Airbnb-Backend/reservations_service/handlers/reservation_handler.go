package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"reservations_service/data"
	"strings"
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
		if err.Error() == "Reservation already exists for the specified dates and accommodation." {
			s.logger.Print("No one else can book accommodation for the reserved dates. ")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("No one else can book accommodation for the reserved dates"))
		} else if err.Error() == "Can not reserve a date that does not exist in appointments." {
			s.logger.Print("Can not reserve a date that does not exist in appointments.")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Can not reserve a date that does not exist in appointments."))
		} else if err.Error() == "Error creating reservation. Cannot create reservation in the past." {
			s.logger.Print("Error creating reservation. Cannot create reservation in the past.")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error creating reservation. Cannot create reservation in the past."))
		} else {
			s.logger.Print("Database exception: ", err)
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error creating reservation."))
		}
		return
	}
	rw.WriteHeader(http.StatusOK)
	s.logger.Print("Reservation created succesfully")
}

func (s *ReservationHandler) CancelReservation(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	reservationID := vars["id"]

	err := s.reservationRepo.CancelReservation(reservationID)
	if err != nil {
		if err.Error() == "Can not cancel reservation. You can only cancel it before it starts." {
			s.logger.Print("Can not cancel reservation. You can only cancel it before it starts. ")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Can not cancel reservation. You can only cancel it before it starts."))
		} else {
			s.logger.Print("Error cancelling reservation: ", err)
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte("Error cancelling reservation."))
		}
		return
	}

	rw.WriteHeader(http.StatusOK)
	s.logger.Print("Reservation cancelled succesfully")
	rw.Write([]byte("Reservation cancelled successfully."))
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

func (s *ReservationHandler) CheckHostReservations(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	userID := vars["id"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		s.logger.Println("Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	hasReservations, err := s.reservationRepo.HasReservationsForHost(userID, authToken)
	if err != nil {
		s.logger.Println("Error checking host reservations:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(rw).Encode(hasReservations); err != nil {
		s.logger.Println("Error encoding JSON response:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func extractBearerToken(authHeader string) string {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
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
