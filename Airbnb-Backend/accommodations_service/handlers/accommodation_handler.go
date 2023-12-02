package handlers

import (
	"accommodations_service/data"
	"context"
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson"
	"log"
	"net/http"
	"regexp"
	"strconv"
)

type KeyProduct struct{}

type AccommodationHandler struct {
	logger *log.Logger
	repo   *data.AccommodationRepo
}

type ValidationError struct {
	Message string `json:"message"`
}

func NewAccommodationHandler(l *log.Logger, r *data.AccommodationRepo) *AccommodationHandler {
	return &AccommodationHandler{l, r}
}

func (s *AccommodationHandler) CreateAccommodation(rw http.ResponseWriter, h *http.Request) {

	accommodation := h.Context().Value(KeyProduct{}).(*data.Accommodation)

	if err := validateAccommodation(accommodation); err != nil {
		http.Error(rw, err.Message, http.StatusUnprocessableEntity)
		return
	}

	err := s.repo.InsertAccommodation(accommodation)
	if err != nil {
		s.logger.Print("Database exception: ", err)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (s *AccommodationHandler) GetAll(rw http.ResponseWriter, h *http.Request) {

	accommodations, err := s.repo.GetAll()
	if err != nil {
		s.logger.Print("Database exception: ", err)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(accommodations)
	rw.WriteHeader(http.StatusOK)
}

func (s *AccommodationHandler) SearchAccommodations(rw http.ResponseWriter, h *http.Request) {

	location := h.URL.Query().Get("location")
	minGuests := h.URL.Query().Get("minGuests")

	minGuestsInt, err := strconv.Atoi(minGuests)
	if err != nil {
		http.Error(rw, "Invalid minGuests parameter", http.StatusBadRequest)
		return
	}

	filter := bson.M{}
	if location != "" {
		filter["location.country"] = location
	}
	if minGuests != "" {
		// Condition to filter by Guests
		filter["$and"] = bson.A{
			bson.M{"minGuest": bson.M{"$lte": minGuestsInt}},
			bson.M{"maxGuest": bson.M{"$gte": minGuestsInt}},
		}
	}

	accommodations, err := s.repo.Search(filter)
	if err != nil {
		s.logger.Print("Database exception: ", err)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(accommodations)
	rw.WriteHeader(http.StatusOK)
}

func validateAccommodation(accommodation *data.Accommodation) *ValidationError {
	nameRegex := regexp.MustCompile(`^[a-zA-Z0-9\s,'-]{3,35}$`)
	descriptionRegex := regexp.MustCompile(`^[a-zA-Z0-9\s,'-]{3,200}$`)
	imagesRegex := regexp.MustCompile(`^[a-zA-Z0-9\s,'-]{3,200}$`)
	countryRegex := regexp.MustCompile(`^[A-Z][a-zA-Z\s-]{2,35}$`)
	cityRegex := regexp.MustCompile(`^[A-Z][a-zA-Z\s-]{2,35}$`)
	streetRegex := regexp.MustCompile(`^[A-Z][a-zA-Z0-9\s,'-]{2,35}$`)
	benefitsRegex := regexp.MustCompile(`^[a-zA-Z0-9\s,'-]{3,100}$`)

	if accommodation.Name == "" {
		return &ValidationError{Message: "Name cannot be empty"}
	}
	if !nameRegex.MatchString(accommodation.Name) {
		return &ValidationError{Message: "Invalid 'Name' format. It must be 3-35 characters long and contain only letters, numbers, spaces, commas, apostrophes, and hyphens"}
	}

	if accommodation.Description == "" {
		return &ValidationError{Message: "Description cannot be empty"}
	}
	if !descriptionRegex.MatchString(accommodation.Description) {
		return &ValidationError{Message: "Invalid 'Description' format. It must be 3-200 characters long and contain only letters, numbers, spaces, commas, apostrophes, and hyphens"}
	}

	if accommodation.Images == "" {
		return &ValidationError{Message: "Images cannot be empty"}
	}
	if !imagesRegex.MatchString(accommodation.Images) {
		return &ValidationError{Message: "Invalid 'Images' format. It must be 3-200 characters long and contain only letters, numbers, spaces, commas, apostrophes, and hyphens"}
	}

	if accommodation.Benefits == "" {
		return &ValidationError{Message: "Benefits cannot be empty"}
	}
	if !benefitsRegex.MatchString(accommodation.Benefits) {
		return &ValidationError{Message: "Invalid 'Benefits' format. It must be 3-100 characters long and contain only letters, numbers, spaces, commas, apostrophes, and hyphens"}
	}

	if accommodation.Location.Country == "" {
		return &ValidationError{Message: "Country cannot be empty"}
	}
	if !countryRegex.MatchString(accommodation.Location.Country) {
		return &ValidationError{Message: "Invalid 'Country' format. It must start with an uppercase letter, followed by letters, spaces, or hyphens, and be 2-35 characters long"}
	}

	if accommodation.Location.City == "" {
		return &ValidationError{Message: "City cannot be empty"}
	}
	if !cityRegex.MatchString(accommodation.Location.City) {
		return &ValidationError{Message: "Invalid 'City' format. It must start with an uppercase letter, followed by letters, spaces, or hyphens, and be 2-35 characters long"}
	}

	if accommodation.Location.Street == "" {
		return &ValidationError{Message: "Street cannot be empty"}
	}
	if !streetRegex.MatchString(accommodation.Location.Street) {
		return &ValidationError{Message: "Invalid 'Street' format. It must start with an uppercase letter, followed by letters, numbers, spaces, commas, apostrophes, or hyphens, and be 2-50 characters long"}
	}

	if accommodation.Location.Number <= 0 {
		return &ValidationError{Message: "Number in Location should be a positive integer"}
	}

	if accommodation.MinGuest <= 0 {
		return &ValidationError{Message: "MinGuest should be a non-negative integer"}
	}
	if accommodation.MaxGuest < accommodation.MinGuest {
		return &ValidationError{Message: "MaxGuest should be greater than or equal to MinGuest"}
	}

	if accommodation.OwnerId == "" {
		return &ValidationError{Message: "OwnerId cannot be empty"}
	}

	return nil
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
