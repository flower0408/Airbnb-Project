package handlers

import (
	"context"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"reservations_service/data"
)

type AppointmentHandler struct {
	logger          *log.Logger
	appointmentRepo *data.AppointmentRepo
}

func NewAppointmentHandler(l *log.Logger, r *data.AppointmentRepo) *AppointmentHandler {
	return &AppointmentHandler{l, r}
}

// mongo
func (r *AppointmentHandler) CreateAppointment(rw http.ResponseWriter, h *http.Request) {
	appointment := h.Context().Value(KeyProduct{}).(*data.Appointment)
	err := r.appointmentRepo.InsertAppointment(appointment)
	if err != nil {
		r.logger.Print("Database exception: ", err)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (r *AppointmentHandler) UpdateAppointment(rw http.ResponseWriter, h *http.Request) {

	vars := mux.Vars(h)
	id := vars["id"]

	appointment := h.Context().Value(KeyProduct{}).(*data.Appointment)

	r.appointmentRepo.UpdateAppointment(id, appointment)
	rw.WriteHeader(http.StatusOK)
}

func (r *AppointmentHandler) CreatePriceForInterval(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	id := vars["id"]
	priceForInterval := h.Context().Value(KeyProduct{}).(*data.PriceForInterval)

	r.appointmentRepo.AddPriceForIntervalForAppointment(id, priceForInterval)
	rw.WriteHeader(http.StatusOK)
}

func (r *AppointmentHandler) UpdatePriceForInterval(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	id := vars["id"]
	intervalId := vars["intervalId"]
	priceForInterval := h.Context().Value(KeyProduct{}).(*data.PriceForInterval)

	r.appointmentRepo.EditPriceForIntervalForAppointment(id, intervalId, priceForInterval)
	rw.WriteHeader(http.StatusOK)
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

func (s *AppointmentHandler) MiddlewarePriceForIntervalDeserialization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, h *http.Request) {
		price := &data.PriceForInterval{}
		err := price.FromJSON(h.Body)
		if err != nil {
			http.Error(rw, "Unable to decode json", http.StatusBadRequest)
			s.logger.Fatal(err)
			return
		}
		ctx := context.WithValue(h.Context(), KeyProduct{}, price)
		h = h.WithContext(ctx)
		next.ServeHTTP(rw, h)
	})
}
