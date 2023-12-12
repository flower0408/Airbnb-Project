package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
	"net/http"
	"os"
	"reservations_service/data"
)

type AppointmentHandler struct {
	logger          *log.Logger
	appointmentRepo *data.AppointmentRepo
}

var (
	accommodationServiceHost = os.Getenv("ACCOMMODATIONS_SERVICE_HOST")
	accommodationServicePort = os.Getenv("ACCOMMODATIONS_SERVICE_PORT")
)

func NewAppointmentHandler(l *log.Logger, r *data.AppointmentRepo) *AppointmentHandler {
	return &AppointmentHandler{l, r}
}

// mongo
func (r *AppointmentHandler) CreateAppointment(rw http.ResponseWriter, h *http.Request) {
	appointment := h.Context().Value(KeyProduct{}).(*data.Appointment)
	err := r.appointmentRepo.InsertAppointment(appointment)
	if err != nil {
		if err.Error() == "Error adding appointment. Date already exists. " {
			r.logger.Print("Error adding appointment. Date already exists. ")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error adding appointment. Date already exists. "))
		} else if err.Error() == "Error adding appointment. Cannot add appointment in the past." {
			r.logger.Print("Error adding appointment. Cannot add appointment in the past.")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error adding appointment. Cannot add appointment in the past."))
		} else {
			r.logger.Print("Database exception: ", err)
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error creating reservation."))
		}
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (r *AppointmentHandler) GetAllAppointment(rw http.ResponseWriter, h *http.Request) {
	appointments, err := r.appointmentRepo.GetAllAppointment()
	if err != nil {
		r.logger.Print("Database exception")
	}

	if appointments == nil {
		return
	}

	err = appointments.ToJSON(rw)
	if err != nil {
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		r.logger.Fatal("Unable to convert to json")
		return
	}
}

func (r *AppointmentHandler) GetAppointmentsByAccommodation(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	id := vars["id"]

	appointments, err := r.appointmentRepo.GetAppointmentsByAccommodation(id)
	if err != nil {
		r.logger.Print("Database exception")
	}

	if appointments == nil {
		return
	}

	err = appointments.ToJSON(rw)
	if err != nil {
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		r.logger.Fatal("Unable to convert to json")
		return
	}
}

func (r *AppointmentHandler) UpdateAppointment(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	id := vars["id"]

	appointment := h.Context().Value(KeyProduct{}).(*data.Appointment)

	err := r.appointmentRepo.UpdateAppointment(id, appointment)
	if err != nil {
		if err.Error() == "Reservation exists for the appointment." {
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Reservation exists for the appointment. Update not allowed."))
		} else if err.Error() == "Error editing appointment. Date already exists. " {
			r.logger.Print("Error editing appointment. Date already exists. ")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error editing appointment. Date already exists. "))
		} else if err.Error() == "Error editing appointment. Cannot add appointment in the past." {
			r.logger.Print("Error editing appointment. Cannot add appointment in the past.")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error editing appointment. Cannot add appointment in the past."))
		} else {
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error updating appointment."))
		}
		return
	}

	rw.WriteHeader(http.StatusOK)
}

func (r *AppointmentHandler) DeleteAppointmentsByAccommodationIDs(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	userId := vars["id"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		r.logger.Println("Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	accommodationEndpoint := fmt.Sprintf("http://%s:%s/owner/%s", accommodationServiceHost, accommodationServicePort, userId)
	accommodationRequest, err := http.NewRequest("GET", accommodationEndpoint, nil)
	if err != nil {
		r.logger.Println("Error creating accommodation request:", err)
		rw.Write([]byte("Error creating accommodation request"))
		return
	}

	accommodationRequest.Header.Set("Authorization", "Bearer "+authToken)

	accommodationResponse, err := http.DefaultClient.Do(accommodationRequest)
	if err != nil {
		r.logger.Println("Error sending accommodation request:", err)
		rw.Write([]byte("Error sending accommodation request"))
		return
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		r.logger.Println("Accommodation service returned an error:", accommodationResponse.Status)
		rw.Write([]byte("Accommodation service returned an error"))
		return
	}

	var accommodations []primitive.ObjectID

	err = json.NewDecoder(accommodationResponse.Body).Decode(&accommodations)
	if err != nil {
		r.logger.Println("Error decoding accommodation response:", err)
		rw.Write([]byte("Error decoding accommodation response"))
		return
	}

	defer accommodationResponse.Body.Close()
	for _, accommodationID := range accommodations {
		err := r.appointmentRepo.DeleteAppointmentsByAccommodationID(accommodationID.Hex())
		if err != nil {
			r.logger.Print("Database exception:", err)
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte("Error deleting appointments"))
			return
		}
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("Appointments deleted successfully"))
}

func (s *AppointmentHandler) MiddlewareAppointmentDeserialization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, h *http.Request) {
		appointments := &data.Appointment{}
		err := appointments.FromJSON(h.Body)
		if err != nil {
			http.Error(rw, "Unable to decode json", http.StatusBadRequest)
			s.logger.Fatal(err)
			return
		}
		ctx := context.WithValue(h.Context(), KeyProduct{}, appointments)
		h = h.WithContext(ctx)
		next.ServeHTTP(rw, h)
	})
}
