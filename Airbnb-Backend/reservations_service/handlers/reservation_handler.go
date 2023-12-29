package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/cristalhq/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/sony/gobreaker"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
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
	tracer          trace.Tracer
	cb              *gobreaker.CircuitBreaker
	cb2             *gobreaker.CircuitBreaker
}

func NewReservationHandler(l *log.Logger, r *data.ReservationRepo, t trace.Tracer) *ReservationHandler {
	return &ReservationHandler{
		logger:          l,
		reservationRepo: r,
		tracer:          t,
		cb:              CircuitBreaker("reservationService"),
		cb2:             CircuitBreaker("reservationService2"),
	}
}

func (s *ReservationHandler) CreateReservation(rw http.ResponseWriter, h *http.Request) {
	ctx, span := s.tracer.Start(h.Context(), "ReservationHandler.CreateReservation")
	defer span.End()

	var (
		createdReservationID string
	)

	reservation := h.Context().Value(KeyProduct{}).(*data.Reservation)
	createdReservation, err := s.reservationRepo.InsertReservation(ctx, reservation)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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

	createdReservationID = createdReservation.ID.String()
	s.logger.Print("Reservation created successfully: ", createdReservation)

	s.logger.Print("AccommodationId: ", createdReservation.AccommodationId)

	// Circuit breaker for accommodation service
	resultAccommodation, breakerErrAccommodation := s.cb.Execute(func() (interface{}, error) {

		accommodationDetailsEndpoint := fmt.Sprintf("http://%s:%s/%s", accommodationServiceHost, accommodationServicePort, createdReservation.AccommodationId)
		accommodationDetailsRequest, _ := http.NewRequest("GET", accommodationDetailsEndpoint, nil)
		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(accommodationDetailsRequest.Header))
		accommodationDetailsResponse, err := http.DefaultClient.Do(accommodationDetailsRequest)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("Error fetching accommodation details: %v", err)
		}
		defer accommodationDetailsResponse.Body.Close()

		if accommodationDetailsResponse.StatusCode != http.StatusOK {
			span.SetStatus(codes.Error, "Error fetching accommodation details")
			return nil, fmt.Errorf("Error fetching accommodation details. Status code: %d", accommodationDetailsResponse.StatusCode)
		}

		body, err := ioutil.ReadAll(accommodationDetailsResponse.Body)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("Error reading accommodation details response: %v", err)
		}

		var accommodationDetails AccommodationDetails
		err = json.Unmarshal(body, &accommodationDetails)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("Error unmarshaling accommodation details JSON: %v", err)
		}

		return &accommodationDetails, nil
	})

	if breakerErrAccommodation != nil {
		span.SetStatus(codes.Error, breakerErrAccommodation.Error())
		log.Printf("Circuit breaker error: %v", breakerErrAccommodation)
		log.Println("Before http.Error")

		rw.WriteHeader(http.StatusServiceUnavailable)

		http.Error(rw, "Error getting accommodation service", http.StatusServiceUnavailable)

		log.Println("After http.Error")

		err := s.reservationRepo.DeleteReservation(ctx, createdReservationID)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			log.Printf("Error deleting reservation after circuit breaker error: %v", err)
		}

		return
	}

	accommodationDetails := resultAccommodation.(*AccommodationDetails)

	fmt.Println("OwnerId:", accommodationDetails.OwnerId)
	fmt.Println("Name:", accommodationDetails.Name)

	// Circuit breaker for notification service
	resultNotification, breakerErrNotification := s.cb2.Execute(func() (interface{}, error) {

		requestBody := map[string]interface{}{
			"ByGuestId":   createdReservation.ByUserId,
			"ForHostId":   accommodationDetails.OwnerId,
			"Description": fmt.Sprintf("Guest for period %s created reservation for accommodation  %s", createdReservation.Period, accommodationDetails.Name),
		}

		body, err := json.Marshal(requestBody)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("Error marshaling requestBody details JSON: %v", err)
		}

		notificationServiceEndpoint := fmt.Sprintf("http://%s:%s/", notificationServiceHost, notificationServicePort)
		notificationServiceRequest, _ := http.NewRequest("POST", notificationServiceEndpoint, bytes.NewReader(body))
		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(notificationServiceRequest.Header))
		responseUser, err := http.DefaultClient.Do(notificationServiceRequest)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("Error fetching notification service: %v", err)
		}
		defer responseUser.Body.Close()

		if responseUser.StatusCode != http.StatusOK {
			buf := new(strings.Builder)
			_, _ = io.Copy(buf, responseUser.Body)
			errorMessage := fmt.Sprintf("UserServiceError: %s", buf.String())
			return nil, fmt.Errorf(errorMessage)
		}

		return responseUser, nil
	})

	if breakerErrNotification != nil {
		span.SetStatus(codes.Error, breakerErrNotification.Error())
		log.Printf("Circuit breaker error: %v", breakerErrNotification)
		log.Println("Before http.Error")

		rw.WriteHeader(http.StatusServiceUnavailable)

		http.Error(rw, "Error getting notification service", http.StatusServiceUnavailable)

		log.Println("After http.Error")

		err := s.reservationRepo.DeleteReservation(ctx, createdReservationID)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			log.Printf("Error deleting reservation after circuit breaker error: %v", err)
		}

		return
	}

	s.logger.Println("Code after circuit breaker execution")

	if resultNotification != nil {

		fmt.Println("Received meaningful data:", resultNotification)
	}

	rw.WriteHeader(http.StatusOK)
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
	ctx, span := s.tracer.Start(h.Context(), "ReservationHandler.CancelReservation")
	defer span.End()

	vars := mux.Vars(h)
	reservationID := vars["id"]

	reservation, err := s.reservationRepo.GetReservationByID(ctx, reservationID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.logger.Print("Error retrieving reservation: ", err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error retrieving reservation."))
		return
	}

	s.logger.Print("AccommodationId: ", reservation.AccommodationId)

	// Circuit breaker for accommodation service
	resultAccommodation, breakerErrAccommodation := s.cb.Execute(func() (interface{}, error) {
		accommodationDetailsEndpoint := fmt.Sprintf("http://%s:%s/%s", accommodationServiceHost, accommodationServicePort, reservation.AccommodationId)
		accommodationDetailsRequest, _ := http.NewRequest("GET", accommodationDetailsEndpoint, nil)
		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(accommodationDetailsRequest.Header))
		accommodationDetailsResponse, err := http.DefaultClient.Do(accommodationDetailsRequest)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("Error fetching accommodation details: %v", err)
		}
		defer accommodationDetailsResponse.Body.Close()

		if accommodationDetailsResponse.StatusCode != http.StatusOK {
			span.SetStatus(codes.Error, "Error fetching accommodation details")
			return nil, fmt.Errorf("Error fetching accommodation details. Status code: %d", accommodationDetailsResponse.StatusCode)
		}

		body, err := ioutil.ReadAll(accommodationDetailsResponse.Body)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("Error reading accommodation details response: %v", err)
		}

		var accommodationDetails AccommodationDetails
		err = json.Unmarshal(body, &accommodationDetails)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("Error unmarshaling accommodation details JSON: %v", err)
		}

		return &accommodationDetails, nil
	})

	if breakerErrAccommodation != nil {
		span.SetStatus(codes.Error, breakerErrAccommodation.Error())
		log.Printf("Circuit breaker error: %v", breakerErrAccommodation)
		log.Println("Before http.Error")

		rw.WriteHeader(http.StatusServiceUnavailable)

		http.Error(rw, "Error getting accommodation service", http.StatusServiceUnavailable)

		log.Println("After http.Error")

		return
	}

	accommodationDetails := resultAccommodation.(*AccommodationDetails)

	fmt.Println("OwnerId:", accommodationDetails.OwnerId)
	fmt.Println("OwnerId:", accommodationDetails.Name)

	err = s.reservationRepo.CancelReservation(ctx, reservationID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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

	// Circuit breaker for notification service
	resultNotification, breakerErrNotification := s.cb2.Execute(func() (interface{}, error) {

		requestBody := map[string]interface{}{
			"ByGuestId":   reservation.ByUserId,
			"ForHostId":   accommodationDetails.OwnerId,
			"Description": fmt.Sprintf("Guest for period %s canceled reservation for accommodation  %s", reservation.Period, accommodationDetails.Name),
		}

		body, err := json.Marshal(requestBody)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("Error marshaling requestBody details JSON: %v", err)
		}

		notificationServiceEndpoint := fmt.Sprintf("http://%s:%s/", notificationServiceHost, notificationServicePort)
		notificationServiceRequest, _ := http.NewRequest("POST", notificationServiceEndpoint, bytes.NewReader(body))
		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(notificationServiceRequest.Header))
		responseUser, err := http.DefaultClient.Do(notificationServiceRequest)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("Error fetching notification service: %v", err)
		}
		defer responseUser.Body.Close()

		if responseUser.StatusCode != http.StatusOK {
			buf := new(strings.Builder)
			_, _ = io.Copy(buf, responseUser.Body)
			errorMessage := fmt.Sprintf("UserServiceError: %s", buf.String())
			return nil, fmt.Errorf(errorMessage)
		}

		return responseUser, nil
	})

	if breakerErrNotification != nil {
		span.SetStatus(codes.Error, breakerErrNotification.Error())
		log.Printf("Circuit breaker error: %v", breakerErrNotification)
		log.Println("Before http.Error")

		rw.WriteHeader(http.StatusServiceUnavailable)

		http.Error(rw, "Error getting notification service", http.StatusServiceUnavailable)

		log.Println("After http.Error")

		return
	}

	s.logger.Println("Code after circuit breaker execution")

	if resultNotification != nil {

		fmt.Println("Received meaningful data:", resultNotification)
	}

	/*err = s.reservationRepo.CancelReservation(reservationID)
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
	}*/

	rw.WriteHeader(http.StatusOK)
	s.logger.Print("Reservation cancelled succesfully")

}

func (s *ReservationHandler) GetReservationByUser(rw http.ResponseWriter, h *http.Request) {
	ctx, span := s.tracer.Start(h.Context(), "ReservationHandler.GetReservationByUser")
	defer span.End()

	bearer := h.Header.Get("Authorization")
	if bearer == "" {
		span.SetStatus(codes.Error, "Authorization header missing")
		log.Println("Authorization header missing")
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bearerToken := strings.Split(bearer, "Bearer ")
	if len(bearerToken) != 2 {
		span.SetStatus(codes.Error, "Malformed header missing")
		log.Println("Malformed Authorization header")
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := bearerToken[1]
	log.Printf("Token: %s\n", tokenString)

	token, err := jwt.Parse([]byte(tokenString), verifier)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
		userID, statusCode, err := s.getUserIDFromUserService(ctx, username)
		return map[string]interface{}{"userID": userID, "statusCode": statusCode, "err": err}, err
	})

	if breakerErr != nil {
		span.SetStatus(codes.Error, breakerErr.Error())
		log.Println("Circuit breaker open:", breakerErr)
		http.Error(rw, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		span.SetStatus(codes.Error, "Internal server error: Unexpected result type")
		log.Println("Internal server error: Unexpected result type")
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID, ok := resultMap["userID"].(string)
	if !ok {
		span.SetStatus(codes.Error, "Internal server error: User ID not found in the response")
		log.Println("Internal server error: User ID not found in the response")
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}

	statusCode, ok := resultMap["statusCode"].(int)
	if !ok {
		span.SetStatus(codes.Error, "Internal server error: Status code not found in the response")
		log.Println("Internal server error: Status code not found in the response")
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err, ok := resultMap["err"].(error); ok && err != nil {
		span.SetStatus(codes.Error, err.Error())
		log.Println("Error from user service:", err)
		http.Error(rw, err.Error(), statusCode)
		return
	}

	reservationByUser, err := s.reservationRepo.GetReservationByUser(ctx, userID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.logger.Print("Database exception: ", err)
		http.Error(rw, "Error getting reservations", http.StatusInternalServerError)
		return
	}

	if reservationByUser == nil {
		span.SetStatus(codes.Error, "Reservation not found")
		http.Error(rw, "Reservations not found", http.StatusNotFound)
		return
	}

	err = reservationByUser.ToJSON(rw)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		s.logger.Fatal("Unable to convert to json :", err)
		return
	}
}

func (s *ReservationHandler) getUserIDFromUserService(ctx context.Context, username interface{}) (string, int, error) {
	ctx, span := s.tracer.Start(ctx, "ReservationHandler.getUserIDFromUserService")
	defer span.End()

	userServiceEndpoint := fmt.Sprintf("http://%s:%s/getOne/%s", userServiceHost, userServicePort, username)
	userServiceRequest, _ := http.NewRequest("GET", userServiceEndpoint, nil)
	log.Printf("Host: %s, Port: %s, Username: %s\n", userServiceHost, userServicePort, username)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(userServiceRequest.Header))
	response, err := http.DefaultClient.Do(userServiceRequest)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return "", http.StatusInternalServerError, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "User not found in database")
		return "", response.StatusCode, fmt.Errorf("User not found in database")
	}

	var user map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&user); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return "", http.StatusInternalServerError, err
	}

	userID, ok := user["id"].(string)
	if !ok {
		span.SetStatus(codes.Error, "User ID not found in the response")
		return "", http.StatusInternalServerError, fmt.Errorf("User ID not found in the response")
	}

	return userID, http.StatusOK, nil
}

func (s *ReservationHandler) GetReservationByAccommodation(rw http.ResponseWriter, h *http.Request) {
	ctx, span := s.tracer.Start(h.Context(), "ReservationHandler.GetReservationByAccommodation")
	defer span.End()

	vars := mux.Vars(h)
	id := vars["id"]

	reservationByUser, err := s.reservationRepo.GetReservationByAccommodation(ctx, id)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.logger.Print("Database exception: ", err)
	}

	if reservationByUser == nil {
		return
	}

	err = reservationByUser.ToJSON(rw)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
	ctx, span := s.tracer.Start(h.Context(), "ReservationHandler.CheckReservation")
	defer span.End()

	var requestBody struct {
		AccommodationID string   `json:"accommodationId"`
		Available       []string `json:"available"`
	}

	err := json.NewDecoder(h.Body).Decode(&requestBody)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(rw, "Unable to decode JSON", http.StatusBadRequest)
		s.logger.Println("Error decoding JSON:", err)
		return
	}

	// Pretvori stringove u time.Time
	var available []time.Time
	for _, t := range requestBody.Available {
		parsedTime, err := time.Parse(time.RFC3339, t)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			http.Error(rw, "Invalid time format in JSON", http.StatusBadRequest)
			s.logger.Println("Error parsing time:", err)
			return
		}
		available = append(available, parsedTime)
	}
	fmt.Println(available, "Available check reservation")

	exists, err := s.reservationRepo.ReservationExistsForAppointment(ctx, requestBody.AccommodationID, available)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
	ctx, span := s.tracer.Start(h.Context(), "ReservationHandler.CheckHostReservations")
	defer span.End()

	vars := mux.Vars(h)
	userID := vars["id"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		span.SetStatus(codes.Error, "Error extracting Bearer token")
		s.logger.Println("Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	hasReservations, err := s.reservationRepo.HasReservationsForHost(ctx, userID, authToken)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.logger.Println("Error checking host reservations:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(rw).Encode(hasReservations); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.logger.Println("Error encoding JSON response:", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (rh *ReservationHandler) CheckUserPastReservations(w http.ResponseWriter, r *http.Request) {
	ctx, span := rh.tracer.Start(r.Context(), "ReservationHandler.CheckUserPastReservations")
	defer span.End()

	userID := mux.Vars(r)["id"]
	hostID := mux.Vars(r)["hostId"]

	authHeader := r.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		span.SetStatus(codes.Error, "Error extracting Bearer token")
		rh.logger.Println("Error extracting Bearer token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	hasPastReservations, err := rh.reservationRepo.CheckUserPastReservations(ctx, userID, hostID, authToken)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		log.Println("Error checking user past reservations:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Println(hasPastReservations)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(hasPastReservations)
}

func (rh *ReservationHandler) CheckUserPastReservationsInAccommodation(w http.ResponseWriter, r *http.Request) {
	ctx, span := rh.tracer.Start(r.Context(), "ReservationHandler.CheckUserPastReservationsInAccommodation")
	defer span.End()

	userID := mux.Vars(r)["id"]
	accommodationID := mux.Vars(r)["accommodationId"]

	authHeader := r.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		span.SetStatus(codes.Error, "Error extracting Bearer token")
		rh.logger.Println("Error extracting Bearer token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	hasPastReservations, err := rh.reservationRepo.CheckUserPastReservationsInAccommodation(ctx, userID, accommodationID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		log.Println("Error checking user past reservations:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Println(hasPastReservations)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(hasPastReservations)
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

func ExtractTraceInfoMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
