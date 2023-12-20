package handlers

import (
	"accommodations_service/authorization"
	"accommodations_service/data"
	"accommodations_service/errors"
	"context"
	"encoding/json"
	"fmt"
	"github.com/cristalhq/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/sony/gobreaker"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
)

var (
	jwtKey                 = []byte(os.Getenv("SECRET_KEY"))
	verifier, _            = jwt.NewVerifierHS(jwt.HS256, jwtKey)
	userServiceHost        = os.Getenv("USER_SERVICE_HOST")
	userServicePort        = os.Getenv("USER_SERVICE_PORT")
	reservationServiceHost = os.Getenv("RESERVATIONS_SERVICE_HOST")
	reservationServicePort = os.Getenv("RESERVATIONS_SERVICE_PORT")
)

type KeyProduct struct{}

type AccommodationHandler struct {
	logger *log.Logger
	repo   *data.AccommodationRepo
	cb     *gobreaker.CircuitBreaker
}

type ValidationError struct {
	Message string `json:"message"`
}

func NewAccommodationHandler(l *log.Logger, r *data.AccommodationRepo) *AccommodationHandler {
	return &AccommodationHandler{
		logger: l,
		repo:   r,
		cb:     CircuitBreaker("accommodationService"),
	}
}

func (s *AccommodationHandler) CreateAccommodation(writer http.ResponseWriter, req *http.Request) {
	bearer := req.Header.Get("Authorization")
	if bearer == "" {
		log.Println("Authorization header missing")
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bearerToken := strings.Split(bearer, "Bearer ")
	if len(bearerToken) != 2 {
		log.Println("Malformed Authorization header")
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := bearerToken[1]
	log.Printf("Token: %s\n", tokenString)

	token, err := jwt.Parse([]byte(tokenString), verifier)
	if err != nil {
		log.Println("Token parsing error:", err)
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims := authorization.GetMapClaims(token.Bytes())
	log.Printf("Token Claims: %+v\n", claims)
	username := claims["username"]

	/*userID, statusCode, err := s.getUserIDFromUserService(username)
	if err != nil {
		http.Error(writer, err.Error(), statusCode)
		return
	}*/

	// Circuit breaker for user service
	result, breakerErr := s.cb.Execute(func() (interface{}, error) {
		userID, statusCode, err := s.getUserIDFromUserService(username)
		return map[string]interface{}{"userID": userID, "statusCode": statusCode, "err": err}, err
	})

	if breakerErr != nil {
		log.Println("Circuit breaker open:", breakerErr)
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		log.Println("Internal server error: Unexpected result type")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID, ok := resultMap["userID"].(string)
	if !ok {
		log.Println("Internal server error: User ID not found in the response")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	statusCode, ok := resultMap["statusCode"].(int)
	if !ok {
		log.Println("Internal server error: Status code not found in the response")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err, ok := resultMap["err"].(error); ok && err != nil {
		log.Println("Error from user service:", err)
		http.Error(writer, err.Error(), statusCode)
		return
	}
	accommodation := req.Context().Value(KeyProduct{}).(*data.Accommodation)

	accommodation.OwnerId = userID

	if err := validateAccommodation(accommodation); err != nil {
		http.Error(writer, err.Message, http.StatusUnprocessableEntity)
		return
	}

	id := ""
	id, err = s.repo.InsertAccommodation(accommodation)
	if err != nil {
		s.logger.Print("Database exception: ", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	responseJSON := map[string]string{"id": id}
	responseBytes, err := json.Marshal(responseJSON)
	if err != nil {
		s.logger.Print("Error encoding response:", err)
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(responseBytes)
	if err != nil {
		s.logger.Print("Error writing response:", err)
	}
}

func (s *AccommodationHandler) CreateRateForAccommodation(writer http.ResponseWriter, req *http.Request) {
	bearer := req.Header.Get("Authorization")
	if bearer == "" {
		log.Println("Authorization header missing")
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bearerToken := strings.Split(bearer, "Bearer ")
	if len(bearerToken) != 2 {
		log.Println("Malformed Authorization header")
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := bearerToken[1]
	log.Printf("Token: %s\n", tokenString)

	token, err := jwt.Parse([]byte(tokenString), verifier)
	if err != nil {
		log.Println("Token parsing error:", err)
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims := authorization.GetMapClaims(token.Bytes())
	log.Printf("Token Claims: %+v\n", claims)
	username := claims["username"]

	// Circuit breaker for user service
	result, breakerErr := s.cb.Execute(func() (interface{}, error) {
		userID, statusCode, err := s.getUserIDFromUserService(username)
		return map[string]interface{}{"userID": userID, "statusCode": statusCode, "err": err}, err
	})

	if breakerErr != nil {
		log.Println("Circuit breaker open:", breakerErr)
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		log.Println("Internal server error: Unexpected result type")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID, ok := resultMap["userID"].(string)
	if !ok {
		log.Println("Internal server error: User ID not found in the response")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	statusCode, ok := resultMap["statusCode"].(int)
	if !ok {
		log.Println("Internal server error: Status code not found in the response")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err, ok := resultMap["err"].(error); ok && err != nil {
		log.Println("Error from user service:", err)
		http.Error(writer, err.Error(), statusCode)
		return
	}
	rate := req.Context().Value(KeyProduct{}).(*data.Rate)

	rate.ByGuestId = userID

	// Get the current time in UTC
	utcTime := time.Now().UTC()

	// Set the desired time zone (CET)
	cetLocation, err := time.LoadLocation("Europe/Belgrade")
	if err != nil {
		fmt.Println("Error loading location:", err)
		return
	}

	// Convert to CET
	cetTime := utcTime.In(cetLocation)

	rate.CreatedAt = cetTime.Format(time.RFC3339)

	if err := validateRate(rate); err != nil {
		http.Error(writer, err.Message, http.StatusUnprocessableEntity)
		return
	}

	_, err = s.repo.InsertRateForAccommodation(rate)
	if err != nil {
		s.logger.Print("Database exception: ", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (s *AccommodationHandler) CreateRateForHost(writer http.ResponseWriter, req *http.Request) {
	bearer := req.Header.Get("Authorization")
	if bearer == "" {
		log.Println("Authorization header missing")
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bearerToken := strings.Split(bearer, "Bearer ")
	if len(bearerToken) != 2 {
		log.Println("Malformed Authorization header")
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := bearerToken[1]
	log.Printf("Token: %s\n", tokenString)

	token, err := jwt.Parse([]byte(tokenString), verifier)
	if err != nil {
		log.Println("Token parsing error:", err)
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims := authorization.GetMapClaims(token.Bytes())
	log.Printf("Token Claims: %+v\n", claims)
	username := claims["username"]

	// Circuit breaker for user service
	result, breakerErr := s.cb.Execute(func() (interface{}, error) {
		userID, statusCode, err := s.getUserIDFromUserService(username)
		return map[string]interface{}{"userID": userID, "statusCode": statusCode, "err": err}, err
	})

	if breakerErr != nil {
		log.Println("Circuit breaker open:", breakerErr)
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		log.Println("Internal server error: Unexpected result type")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID, ok := resultMap["userID"].(string)
	if !ok {
		log.Println("Internal server error: User ID not found in the response")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	statusCode, ok := resultMap["statusCode"].(int)
	if !ok {
		log.Println("Internal server error: Status code not found in the response")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err, ok := resultMap["err"].(error); ok && err != nil {
		log.Println("Error from user service:", err)
		http.Error(writer, err.Error(), statusCode)
		return
	}

	rate := req.Context().Value(KeyProduct{}).(*data.Rate)

	rate.ByGuestId = userID

	// Circuit breaker for reservation service
	resultR, breakerErr := s.cb.Execute(func() (interface{}, error) {
		reservationServiceEndpoint := fmt.Sprintf("http://%s:%s/checkUserPastReservations/%s/%s", reservationServiceHost, reservationServicePort, userID, rate.ForHostId)
		reservationServiceRequest, _ := http.NewRequest(http.MethodGet, reservationServiceEndpoint, nil)
		reservationServiceRequest.Header.Set("Authorization", "Bearer "+tokenString)
		response, err := http.DefaultClient.Do(reservationServiceRequest)
		if err != nil {
			return nil, fmt.Errorf("Error communicating with reservation service")
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Error getting user reservations in reservation service")
		}

		var hasPastReservations bool
		if err := json.NewDecoder(response.Body).Decode(&hasPastReservations); err != nil {
			return nil, fmt.Errorf("Error decoding past reservations response: %v", err)
		}

		return hasPastReservations, nil
	})

	if breakerErr != nil {
		http.Error(writer, breakerErr.Error(), http.StatusServiceUnavailable)
		return
	}

	hasPastReservations, ok := resultR.(bool)
	if !ok {
		log.Println("Error parsing result from reservation service: Unexpected result type")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !hasPastReservations {
		http.Error(writer, "User don't have past reservations in host's accommodations", http.StatusForbidden)
		return
	}

	hasRated, err := s.repo.HasUserRatedHost(userID, rate.ForHostId)
	if err != nil {
		log.Println("Error checking if user has already rated the host:", err)
		http.Error(writer, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if hasRated {
		http.Error(writer, "User has already rated the host", http.StatusForbidden)
		return
	}

	// Get the current time in UTC
	utcTime := time.Now().UTC()

	// Set the desired time zone (CET)
	cetLocation, err := time.LoadLocation("Europe/Belgrade")
	if err != nil {
		fmt.Println("Error loading location:", err)
		return
	}

	// Convert to CET
	cetTime := utcTime.In(cetLocation)

	rate.CreatedAt = cetTime.Format(time.RFC3339)

	if err := validateRate(rate); err != nil {
		http.Error(writer, err.Message, http.StatusUnprocessableEntity)
		return
	}

	_, err = s.repo.InsertRateForHost(rate)
	if err != nil {
		s.logger.Print("Database exception: ", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func extractBearerToken(authHeader string) string {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

/*func (s *AccommodationHandler) DeleteAccommodationsByOwnerID(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	ownerID := vars["ownerID"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		s.logger.Println("Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	reservationServiceEndpoint := fmt.Sprintf("http://%s:%s/deleteAppointments/%s", reservationServiceHost, reservationServicePort, ownerID)
	reservationServiceRequest, _ := http.NewRequest(http.MethodDelete, reservationServiceEndpoint, nil)
	reservationServiceRequest.Header.Set("Authorization", "Bearer "+authToken)
	response, err := http.DefaultClient.Do(reservationServiceRequest)
	if err != nil {
		http.Error(rw, "Error communicating with reservation service", http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		http.Error(rw, "Error deleting appointments in reservation service", http.StatusInternalServerError)
		return
	}

	err = s.repo.DeleteAccommodationsByOwner(ownerID)
	if err != nil {
		s.logger.Print("Database exception")
		http.Error(rw, "Error deleting accommodations", http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("Accommodations deleted successfully"))
}*/

func (s *AccommodationHandler) DeleteAccommodationsByOwnerID(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	ownerID := vars["ownerID"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		s.logger.Println("Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Circuit breaker for reservation service
	result, breakerErr := s.cb.Execute(func() (interface{}, error) {
		reservationServiceEndpoint := fmt.Sprintf("http://%s:%s/deleteAppointments/%s", reservationServiceHost, reservationServicePort, ownerID)
		reservationServiceRequest, _ := http.NewRequest(http.MethodDelete, reservationServiceEndpoint, nil)
		reservationServiceRequest.Header.Set("Authorization", "Bearer "+authToken)
		response, err := http.DefaultClient.Do(reservationServiceRequest)
		if err != nil {
			return nil, fmt.Errorf("Error communicating with reservation service")
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Error deleting appointments in reservation service")
		}

		return nil, nil
	})

	if result != nil {

		fmt.Println("Received meaningful data:", result)
	}

	if breakerErr != nil {
		http.Error(rw, breakerErr.Error(), http.StatusServiceUnavailable)
		return
	}

	err := s.repo.DeleteAccommodationsByOwner(ownerID)
	if err != nil {
		s.logger.Print("Database exception")
		http.Error(rw, "Error deleting accommodations", http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("Accommodations deleted successfully"))
}

func (s *AccommodationHandler) DeleteRateForHost(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	rateID := vars["rateID"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		s.logger.Println("Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	err := s.repo.DeleteRateForHost(rateID)
	if err != nil {
		http.Error(rw, "Error deleting rate for host", http.StatusInternalServerError)
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("Rate deleted successfully"))
}

func (s *AccommodationHandler) getUserIDFromUserService(username interface{}) (string, int, error) {
	userServiceEndpoint := fmt.Sprintf("http://%s:%s/getOne/%s", userServiceHost, userServicePort, username)
	userServiceRequest, _ := http.NewRequest("GET", userServiceEndpoint, nil)
	response, err := http.DefaultClient.Do(userServiceRequest)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", response.StatusCode, fmt.Errorf(errors.NotFoundUserError)
	}

	var user map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&user); err != nil {
		return "", http.StatusInternalServerError, err
	}

	userID, ok := user["id"].(string)
	if !ok {
		return "", http.StatusInternalServerError, fmt.Errorf("User ID not found in the response")
	}

	return userID, http.StatusOK, nil
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

func (s *AccommodationHandler) GetAllRate(rw http.ResponseWriter, h *http.Request) {

	rates, err := s.repo.GetAllRate()
	if err != nil {
		s.logger.Print("Database exception: ", err)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(rates)
	rw.WriteHeader(http.StatusOK)
}

func (s *AccommodationHandler) GetByID(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	id, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	accommodation, err := s.repo.GetByID(id)
	if err != nil {
		s.logger.Print("Database exception: ", err)
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(accommodation)
	rw.WriteHeader(http.StatusOK)
}

func (s *AccommodationHandler) GetRatesByAccommodation(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	id := vars["id"]

	rates, err := s.repo.GetRatesByAccommodation(id)
	if err != nil {
		s.logger.Print("Database exception: ", err)
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(rates)
	rw.WriteHeader(http.StatusOK)
}

func (s *AccommodationHandler) GetAccommodationsByOwner(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	ownerID := vars["ownerID"]

	accommodations, err := s.repo.GetAccommodationsByOwner(ownerID)
	if err != nil {
		s.logger.Print("Database exception: ", err)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(accommodations)

	//resp, err := json.Marshal(accommodations)
	//_, err = rw.Write(resp)
	rw.WriteHeader(http.StatusOK)
}

func (s *AccommodationHandler) SearchAccommodations(rw http.ResponseWriter, h *http.Request) {

	location := h.URL.Query().Get("location")
	minGuests := h.URL.Query().Get("minGuests")
	startDate := h.URL.Query().Get("startDate")
	endDate := h.URL.Query().Get("endDate")

	minGuestsInt, err := strconv.Atoi(minGuests)
	if err != nil {
		http.Error(rw, "Invalid minGuests parameter", http.StatusBadRequest)
		return
	}

	// Check if both start and end dates are empty
	if startDate == "" && endDate == "" {
		// Search without calling reservation service
		filter := bson.M{}
		if location != "" {
			filter["location.country"] = location
		}
		if minGuests != "" {
			filter["$and"] = bson.A{
				bson.M{"minGuest": bson.M{"$lte": minGuestsInt}},
				bson.M{"maxGuest": bson.M{"$gte": minGuestsInt}},
			}
		}

		accommodations, err := s.repo.Search(filter)
		if err != nil {
			s.logger.Print("Database exception: ", err)
			http.Error(rw, "Internal server error", http.StatusInternalServerError)
			return
		}

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		json.NewEncoder(rw).Encode(accommodations)
		return
	}

	appointmentBody := map[string]string{
		"startDate": startDate,
		"endDate":   endDate,
	}

	query := url.Values{}
	for key, value := range appointmentBody {
		query.Add(key, value)
	}

	// Circuit breaker for reservation service
	result, breakerErr := s.cb.Execute(func() (interface{}, error) {
		// Reservation service call
		reservationServiceEndpoint := fmt.Sprintf("http://%s:%s/appointmentsByDate/?%s", reservationServiceHost, reservationServicePort, query.Encode())
		reservationServiceRequest, _ := http.NewRequest("GET", reservationServiceEndpoint, nil)
		reservationServiceResponse, err := http.DefaultClient.Do(reservationServiceRequest)

		if err != nil {
			log.Println("Error making reservation service request:", err)
			http.Error(rw, "Internal server error", http.StatusInternalServerError)
			return nil, fmt.Errorf("ReservationServiceError")
		}
		defer reservationServiceResponse.Body.Close()

		if reservationServiceResponse.StatusCode != http.StatusOK {
			log.Printf("Reservation service responded with status: %d\n", reservationServiceResponse.StatusCode)
			http.Error(rw, "Internal server error", http.StatusInternalServerError)
			return nil, StatusError{Code: http.StatusInternalServerError, Err: "ReservationServiceError"}
		}

		responseBody1, err := ioutil.ReadAll(reservationServiceResponse.Body)
		if err != nil {
			log.Println("Error reading reservation service response body:", err)
			http.Error(rw, "Internal server error", http.StatusInternalServerError)
			return nil, fmt.Errorf("ReservationServiceError")
		}

		//log.Printf("Raw Reservation service response body: %s\n", responseBody1)

		var responseBody []struct {
			AccommodationID string `json:"accommodationId"`
		}
		if err := json.Unmarshal(responseBody1, &responseBody); err != nil {
			log.Println("Error decoding reservation service response:", err)
			http.Error(rw, "Internal server error", http.StatusInternalServerError)
			return nil, fmt.Errorf("ReservationServiceError")
		}

		var availableAccommodationIDs []string
		for _, entry := range responseBody {
			availableAccommodationIDs = append(availableAccommodationIDs, entry.AccommodationID)
		}

		//log.Printf("Available Accommodation IDs: %v\n", availableAccommodationIDs)

		var accommodations []*data.Accommodation
		for _, id := range availableAccommodationIDs {
			objectID, err := primitive.ObjectIDFromHex(id)
			if err != nil {
				log.Printf("Invalid ObjectID (%s): %v\n", id, err)
				continue
			}

			accommodation, err := s.repo.GetByID(objectID)
			if err != nil {
				log.Printf("Accommodation not found for ObjectID (%s)\n", id)
				continue
			}

			accommodations = append(accommodations, accommodation)
		}

		//log.Printf("Retrieved Accommodations: %+v\n", accommodations)

		var filteredAccommodations []*data.Accommodation
		for _, acc := range accommodations {
			if location != "" && acc.Location.Country != location {
				continue
			}

			if minGuests != "" && (acc.MinGuest > minGuestsInt || acc.MaxGuest < minGuestsInt) {
				continue
			}

			filteredAccommodations = append(filteredAccommodations, acc)
		}

		//log.Printf("Filtered Accommodations: %+v\n", filteredAccommodations)

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		json.NewEncoder(rw).Encode(filteredAccommodations)

		return "ReservationServiceOK", nil
	})
	if breakerErr != nil {
		if statusErr, ok := breakerErr.(StatusError); ok {
			http.Error(rw, statusErr.Err, statusErr.Code)
		} else {
			http.Error(rw, breakerErr.Error(), http.StatusServiceUnavailable)
		}
		return
	}

	if result != nil {
		fmt.Println("Received meaningful data:", result)
	}
}

type StatusError struct {
	Code int
	Err  string
}

func (e StatusError) Error() string {
	return e.Err
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

func validateRate(rate *data.Rate) *ValidationError {

	if rate.Rate == 0 {
		return &ValidationError{Message: "Rate cannot be 0"}
	}
	if rate.Rate > 5 || rate.Rate < 1 {
		return &ValidationError{Message: "Rate can be only from 1 to 5"}
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

func (s *AccommodationHandler) MiddlewareRateDeserialization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, h *http.Request) {
		rates := &data.Rate{}
		err := rates.FromJSON(h.Body)
		if err != nil {
			http.Error(rw, "Unable to decode json", http.StatusBadRequest)
			s.logger.Fatal(err)
			return
		}
		ctx := context.WithValue(h.Context(), KeyProduct{}, rates)
		h = h.WithContext(ctx)
		next.ServeHTTP(rw, h)
	})
}

func CircuitBreaker(name string) *gobreaker.CircuitBreaker {
	return gobreaker.NewCircuitBreaker(
		gobreaker.Settings{
			Name:        name,
			MaxRequests: 1,
			Timeout:     10 * time.Second,
			Interval:    0,
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				return counts.ConsecutiveFailures > 2
			},
			OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
				log.Printf("Circuit Breaker '%s' changed from '%s' to '%s'\n", name, from, to)
			},

			IsSuccessful: func(err error) bool {
				if err == nil {
					return true
				}
				errResp, ok := err.(data.ErrResp)
				return ok && errResp.StatusCode >= 400 && errResp.StatusCode < 500
			},
		},
	)
}
