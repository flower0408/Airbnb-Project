package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"log"
	"net/http"
	"os"
	"reservations_service/data"
	"time"
)

type AppointmentHandler struct {
	logger          *log.Logger
	appointmentRepo *data.AppointmentRepo
	tracer          trace.Tracer
}

var (
	accommodationServiceHost = os.Getenv("ACCOMMODATIONS_SERVICE_HOST")
	accommodationServicePort = os.Getenv("ACCOMMODATIONS_SERVICE_PORT")
)

func NewAppointmentHandler(l *log.Logger, r *data.AppointmentRepo, t trace.Tracer) *AppointmentHandler {
	return &AppointmentHandler{l, r, t}
}

// mongo
func (r *AppointmentHandler) CreateAppointment(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.CreateAppointment")
	defer span.End()

	appointment := h.Context().Value(KeyProduct{}).(*data.Appointment)
	err := r.appointmentRepo.InsertAppointment(ctx, appointment)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.GetAllAppointment")
	defer span.End()

	appointments, err := r.appointmentRepo.GetAllAppointment(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		r.logger.Print("Database exception")
	}

	if appointments == nil {
		return
	}

	err = appointments.ToJSON(rw)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		r.logger.Fatal("Unable to convert to json")
		return
	}
}

func (r *AppointmentHandler) GetAppointmentsByAccommodation(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.GetAppointmentsByAccommodation")
	defer span.End()

	vars := mux.Vars(h)
	id := vars["id"]

	appointments, err := r.appointmentRepo.GetAppointmentsByAccommodation(ctx, id)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		r.logger.Print("Database exception")
		http.Error(rw, "Database exception", http.StatusInternalServerError)
		return
	}

	if appointments == nil {
		return
	}

	err = appointments.ToJSON(rw)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		r.logger.Fatal("Unable to convert to json")
		return
	}
}

func (r *AppointmentHandler) GetAppointmentsByDate(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.GetAppointmentsByDate")
	defer span.End()

	startDateStr := h.URL.Query().Get("startDate")
	endDateStr := h.URL.Query().Get("endDate")

	// Parse dates with the specified time zone
	startDate, err := time.Parse(time.RFC3339, startDateStr)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(rw, "Invalid startDate parameter", http.StatusBadRequest)
		return
	}

	endDate, err := time.Parse(time.RFC3339, endDateStr)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(rw, "Invalid endDate parameter", http.StatusBadRequest)
		return
	}

	appointments, err := r.appointmentRepo.GetAppointmentsByDate(ctx, startDate, endDate)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		r.logger.Print("Database exception")
		http.Error(rw, "Unable to retrieve appointments", http.StatusInternalServerError)
		return
	}

	if len(appointments) == 0 {
		return
	}

	accommodationIDs := make(map[string]struct{})
	for _, appointment := range appointments {
		accommodationIDs[appointment.AccommodationId] = struct{}{}
	}

	uniqueAccommodationIDs := make([]string, 0, len(accommodationIDs))
	for id := range accommodationIDs {
		uniqueAccommodationIDs = append(uniqueAccommodationIDs, id)
	}

	fmt.Printf("Unique Accommodation IDs: %+v\n", uniqueAccommodationIDs)

	err = appointments.ToJSON(rw)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(rw, "Unable to convert to JSON", http.StatusInternalServerError)
		r.logger.Fatal("Unable to convert to JSON")
		return
	}
}

func (r *AppointmentHandler) UpdateAppointment(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.UpdateAppointment")
	defer span.End()

	vars := mux.Vars(h)
	id := vars["id"]

	appointment := h.Context().Value(KeyProduct{}).(*data.Appointment)

	err := r.appointmentRepo.UpdateAppointment(ctx, id, appointment)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		if err.Error() == "Reservation exists for the appointment." {
			rw.WriteHeader(http.StatusMethodNotAllowed)
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

	span.SetStatus(codes.Ok, "")
	rw.WriteHeader(http.StatusOK)
}

func (r *AppointmentHandler) DeleteAppointmentsByAccommodationIDs(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.DeleteAppointmentsByAccommodationIDs")
	defer span.End()

	vars := mux.Vars(h)
	userId := vars["id"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		span.SetStatus(codes.Error, "Error extracting Bearer token")
		r.logger.Println("Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	accommodationEndpoint := fmt.Sprintf("http://%s:%s/owner/%s", accommodationServiceHost, accommodationServicePort, userId)
	accommodationRequest, err := http.NewRequest("GET", accommodationEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(accommodationRequest.Header))
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		r.logger.Println("Error creating accommodation request:", err)
		rw.Write([]byte("Error creating accommodation request"))
		return
	}

	accommodationRequest.Header.Set("Authorization", "Bearer "+authToken)

	accommodationResponse, err := http.DefaultClient.Do(accommodationRequest)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		r.logger.Println("Error sending accommodation request:", err)
		rw.Write([]byte("Error sending accommodation request"))
		return
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Accommodation service returned an error")
		r.logger.Println("Accommodation service returned an error:", accommodationResponse.Status)
		rw.Write([]byte("Accommodation service returned an error"))
		return
	}

	var accommodations []primitive.ObjectID

	fmt.Println("lola", accommodations)
	err = json.NewDecoder(accommodationResponse.Body).Decode(&accommodations)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		r.logger.Println("Error decoding accommodation response:", err)
		rw.Write([]byte("Error decoding accommodation response"))
		return
	}

	defer accommodationResponse.Body.Close()
	for _, accommodationID := range accommodations {

		err := r.appointmentRepo.DeleteAppointmentsByAccommodationID(ctx, accommodationID.Hex())
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
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
