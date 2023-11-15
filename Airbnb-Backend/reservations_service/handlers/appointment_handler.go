package handlers

import (
	"context"
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

	//TODO
}

func (r *AppointmentHandler) CreatePriceForInterval(rw http.ResponseWriter, h *http.Request) {
	//TODO
}

func (r *AppointmentHandler) UpdatePriceForInterval(rw http.ResponseWriter, h *http.Request) {
	//TODO
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
