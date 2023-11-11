package handlers

import (
	"accommodations_service/data"
	"context"
	"log"
	"net/http"
)

type KeyProduct struct{}

type AccommodationHandler struct {
	logger *log.Logger
	repo   *data.AccommodationRepo
}

func NewAccommodationHandler(l *log.Logger, r *data.AccommodationRepo) *AccommodationHandler {
	return &AccommodationHandler{l, r}
}

func (s *AccommodationHandler) CreateAccommodation(rw http.ResponseWriter, h *http.Request) {
	accommodation := h.Context().Value(KeyProduct{}).(*data.Accommodation)
	err := s.repo.InsertAccommodation(accommodation)
	if err != nil {
		s.logger.Print("Database exception: ", err)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (s *AccommodationHandler) MiddlewareAccommodationDeserialization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, h *http.Request) {
		accommodations := &data.Accommodation{}
		err := accommodations.FromJSON(h.Body)
		if err != nil {
			http.Error(rw, "Unable to decode json", http.StatusBadRequest)
			s.logger.Fatal(err)
			return
		}
		ctx := context.WithValue(h.Context(), KeyProduct{}, accommodations)
		h = h.WithContext(ctx)
		next.ServeHTTP(rw, h)
	})
}

func (s *AccommodationHandler) MiddlewareContentTypeSet(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, h *http.Request) {
		s.logger.Println("Method [", h.Method, "] - Hit path :", h.URL.Path)

		rw.Header().Add("Content-Type", "application/json")

		next.ServeHTTP(rw, h)
	})
}
