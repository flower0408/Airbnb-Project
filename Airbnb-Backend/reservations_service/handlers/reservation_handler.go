package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/cristalhq/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/sony/gobreaker"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reservations_service/authorization"
	"reservations_service/data"
	"strings"
	"time"
)

type KeyProduct struct{}

var (
	jwtKey                  = []byte(os.Getenv("SECRET_KEY"))
	verifier, _             = jwt.NewVerifierHS(jwt.HS256, jwtKey)
	userServiceHost         = os.Getenv("USER_SERVICE_HOST")
	userServicePort         = os.Getenv("USER_SERVICE_PORT")
	notificationServiceHost = os.Getenv("NOTIFICATION_SERVICE_HOST")
	notificationServicePort = os.Getenv("NOTIFICATION_SERVICE_PORT")
)

type ReservationHandler struct {
	logger          *log.Logger
	reservationRepo *data.ReservationRepo
	cb              *gobreaker.CircuitBreaker
}

func NewReservationHandler(l *log.Logger, r *data.ReservationRepo) *ReservationHandler {
	return &ReservationHandler{
		logger:          l,
		reservationRepo: r,
		cb:              CircuitBreaker("reservationService"),
	}
}

// cassandra
func (s *ReservationHandler) CreateReservation(rw http.ResponseWriter, h *http.Request) {
	reservation := h.Context().Value(KeyProduct{}).(*data.Reservation)
	createdReservation, err := s.reservationRepo.InsertReservation(reservation)
	if err != nil {
		if err.Error() == "Reservation already exists for the specified dates and accommodation." {
			s.logger.Print("No one else can book accommodation for the reserved dates. ")
			rw.WriteHeader(http.StatusMethodNotAllowed)
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
	//s.logger.Print("Reservation created succesfully")
	s.logger.Print("Reservation created successfully: ", createdReservation)

	s.logger.Print("AccommodationId: ", createdReservation.AccommodationId)

	accommodationDetailsEndpoint := fmt.Sprintf("http://%s:%s/%s", accommodationServiceHost, accommodationServicePort, createdReservation.AccommodationId)
	accommodationDetailsRequest, _ := http.NewRequest("GET", accommodationDetailsEndpoint, nil)
	accommodationDetailsResponse, err := http.DefaultClient.Do(accommodationDetailsRequest)
	if err != nil {
		s.logger.Print("Error fetching accommodation details:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error fetching accommodation details."))
		return
	}

	body, err := ioutil.ReadAll(accommodationDetailsResponse.Body)
	if err != nil {
		s.logger.Print("Error reading accommodation details response:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error reading accommodation details response."))
		return
	}

	responseBodyString := string(body)
	log.Printf("Accommodation details response: %s", responseBodyString)

	var accommodationDetails AccommodationDetails
	err = json.Unmarshal(body, &accommodationDetails)
	if err != nil {
		s.logger.Print("Error unmarshaling accommodation details JSON:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error unmarshaling accommodation details JSON."))
		return
	}

	fmt.Println("OwnerId:", accommodationDetails.OwnerId)
	fmt.Println("OwnerId:", accommodationDetails.Name)

	requestBody := map[string]interface{}{
		"ByGuestId":   createdReservation.ByUserId,
		"ForHostId":   accommodationDetails.OwnerId,
		"Description": fmt.Sprintf("Guest for period %s created reservation for accommodation  %s", createdReservation.Period, accommodationDetails.Name),
	}

	body, err = json.Marshal(requestBody)
	if err != nil {
		s.logger.Print("Error marshaling requestBody details JSON:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error marshaling requestBody details JSON."))
		return
	}

	notificationServiceEndpoint := fmt.Sprintf("http://%s:%s/", notificationServiceHost, notificationServicePort)
	notificationServiceRequest, _ := http.NewRequest("POST", notificationServiceEndpoint, bytes.NewReader(body))
	responseUser, err := http.DefaultClient.Do(notificationServiceRequest)

	if err != nil {
		s.logger.Print("Error fetching notification service:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error fetching notification service."))
		return
	}
	defer responseUser.Body.Close()

	if responseUser.StatusCode != http.StatusOK {
		buf := new(strings.Builder)
		_, _ = io.Copy(buf, responseUser.Body)
		errorMessage := fmt.Sprintf("UserServiceError: %s", buf.String())

		s.logger.Print(errorMessage)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(errorMessage))
		return
	}

}

type AccommodationDetails struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Images      string   `json:"images"`
	Location    Location `json:"location"`
	Benefits    string   `json:"benefits"`
	MinGuest    int      `json:"minGuest"`
	MaxGuest    int      `json:"maxGuest"`
	OwnerId     string   `json:"ownerId"`
}
type Location struct {
	Country string `json:"country"`
	City    string `json:"city"`
	Street  string `json:"street"`
	Number  int    `json:"number"`
}

func (s *ReservationHandler) CancelReservation(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	reservationID := vars["id"]

	reservation, err := s.reservationRepo.GetReservationByID(reservationID)
	if err != nil {
		s.logger.Print("Error retrieving reservation: ", err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error retrieving reservation."))
		return
	}

	s.logger.Print("AccommodationId: ", reservation.AccommodationId)

	accommodationDetailsEndpoint := fmt.Sprintf("http://%s:%s/%s", accommodationServiceHost, accommodationServicePort, reservation.AccommodationId)
	accommodationDetailsRequest, _ := http.NewRequest("GET", accommodationDetailsEndpoint, nil)
	accommodationDetailsResponse, err := http.DefaultClient.Do(accommodationDetailsRequest)
	if err != nil {
		s.logger.Print("Error fetching accommodation details:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error fetching accommodation details."))
		return
	}

	body, err := ioutil.ReadAll(accommodationDetailsResponse.Body)
	if err != nil {
		s.logger.Print("Error reading accommodation details response:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error reading accommodation details response."))
		return
	}

	responseBodyString := string(body)
	log.Printf("Accommodation details response: %s", responseBodyString)

	var accommodationDetails AccommodationDetails
	err = json.Unmarshal(body, &accommodationDetails)
	if err != nil {
		s.logger.Print("Error unmarshaling accommodation details JSON:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error unmarshaling accommodation details JSON."))
		return
	}

	fmt.Println("OwnerId:", accommodationDetails.OwnerId)
	fmt.Println("OwnerId:", accommodationDetails.Name)

	requestBody := map[string]interface{}{
		"ByGuestId":   reservation.ByUserId,
		"ForHostId":   accommodationDetails.OwnerId,
		"Description": fmt.Sprintf("Guest for period %s canceled reservation for accommodation  %s", reservation.Period, accommodationDetails.Name),
	}

	body, err = json.Marshal(requestBody)
	if err != nil {
		s.logger.Print("Error marshaling requestBody details JSON:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error marshaling requestBody details JSON."))
		return
	}

	err = s.reservationRepo.CancelReservation(reservationID)
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

	notificationServiceEndpoint := fmt.Sprintf("http://%s:%s/", notificationServiceHost, notificationServicePort)
	notificationServiceRequest, _ := http.NewRequest("POST", notificationServiceEndpoint, bytes.NewReader(body))
	responseUser, err := http.DefaultClient.Do(notificationServiceRequest)

	if err != nil {
		s.logger.Print("Error fetching notification service:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error fetching notification service."))
		return
	}
	defer responseUser.Body.Close()

	if responseUser.StatusCode != http.StatusOK {
		buf := new(strings.Builder)
		_, _ = io.Copy(buf, responseUser.Body)
		errorMessage := fmt.Sprintf("UserServiceError: %s", buf.String())

		s.logger.Print(errorMessage)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(errorMessage))
		return
	}

	rw.WriteHeader(http.StatusOK)
	s.logger.Print("Reservation cancelled succesfully")

}

func (s *ReservationHandler) GetReservationByUser(rw http.ResponseWriter, h *http.Request) {
	bearer := h.Header.Get("Authorization")
	if bearer == "" {
		log.Println("Authorization header missing")
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bearerToken := strings.Split(bearer, "Bearer ")
	if len(bearerToken) != 2 {
		log.Println("Malformed Authorization header")
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := bearerToken[1]
	log.Printf("Token: %s\n", tokenString)

	token, err := jwt.Parse([]byte(tokenString), verifier)
	if err != nil {
		log.Println("Token parsing error:", err)
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims := authorization.GetMapClaims(token.Bytes())
	log.Printf("Token Claims: %+v\n", claims)
	username := claims["username"]

	// Circuit breaker for user service
	log.Printf("Circuit Breaker: %+v\n", s.cb)
	result, breakerErr := s.cb.Execute(func() (interface{}, error) {
		userID, statusCode, err := s.getUserIDFromUserService(username)
		return map[string]interface{}{"userID": userID, "statusCode": statusCode, "err": err}, err
	})

	if breakerErr != nil {
		log.Println("Circuit breaker open:", breakerErr)
		http.Error(rw, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		log.Println("Internal server error: Unexpected result type")
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID, ok := resultMap["userID"].(string)
	if !ok {
		log.Println("Internal server error: User ID not found in the response")
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}

	statusCode, ok := resultMap["statusCode"].(int)
	if !ok {
		log.Println("Internal server error: Status code not found in the response")
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err, ok := resultMap["err"].(error); ok && err != nil {
		log.Println("Error from user service:", err)
		http.Error(rw, err.Error(), statusCode)
		return
	}

	reservationByUser, err := s.reservationRepo.GetReservationByUser(userID)
	if err != nil {
		s.logger.Print("Database exception: ", err)
		http.Error(rw, "Error getting reservations", http.StatusInternalServerError)
		return
	}

	if reservationByUser == nil {
		http.Error(rw, "Reservations not found", http.StatusNotFound)
		return
	}

	err = reservationByUser.ToJSON(rw)
	if err != nil {
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		s.logger.Fatal("Unable to convert to json :", err)
		return
	}
}

func (s *ReservationHandler) getUserIDFromUserService(username interface{}) (string, int, error) {
	userServiceEndpoint := fmt.Sprintf("http://%s:%s/getOne/%s", userServiceHost, userServicePort, username)
	userServiceRequest, _ := http.NewRequest("GET", userServiceEndpoint, nil)
	log.Printf("Host: %s, Port: %s, Username: %s\n", userServiceHost, userServicePort, username)

	response, err := http.DefaultClient.Do(userServiceRequest)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", response.StatusCode, fmt.Errorf("User not found in database")
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

/*func (s *ReservationHandler) GetReservationById(rw http.ResponseWriter, h *http.Request) {
	vars := mux.Vars(h)
	id := vars["id"]

	reservationById, err := s.reservationRepo.GetReservationByID(id)
	if err != nil {
		s.logger.Print("Database exception: ", err)
	}

	if reservationById == nil {
		return
	}

	err = reservationById.ToJSON(rw)
	if err != nil {
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		s.logger.Fatal("Unable to convert to json :", err)
		return
	}
}*/

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
