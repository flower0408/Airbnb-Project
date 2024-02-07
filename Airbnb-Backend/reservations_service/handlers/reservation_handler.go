package handlers

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/cristalhq/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
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
	logger          *logrus.Logger
	reservationRepo *data.ReservationRepo
	tracer          trace.Tracer
	cb              *gobreaker.CircuitBreaker
	cb2             *gobreaker.CircuitBreaker
}

func NewReservationHandler(logger *logrus.Logger, r *data.ReservationRepo, t trace.Tracer) *ReservationHandler {
	return &ReservationHandler{
		logger:          logger,
		reservationRepo: r,
		tracer:          t,
		cb:              CircuitBreaker("reservationService"),
		cb2:             CircuitBreaker("reservationService2"),
	}
}

func (s *ReservationHandler) CreateReservation(rw http.ResponseWriter, h *http.Request) {
	ctx, span := s.tracer.Start(h.Context(), "ReservationHandler.CreateReservation")
	defer span.End()

	s.logger.Infoln("ReservationHandler.CreateReservation : CreateReservation endpoint reached")

	var (
		createdReservationID string
	)

	tokenString, err := extractTokenFromHeader(h)
	if err != nil {
		s.logger.Errorf("ReservationHandler.CreateReservation : No token found")
		span.SetStatus(codes.Error, "No token found")
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("No token found"))
		return
	}

	reservation := h.Context().Value(KeyProduct{}).(*data.Reservation)
	createdReservation, err := s.reservationRepo.InsertReservation(ctx, reservation, tokenString)
	if err != nil {
		span.SetStatus(codes.Error, "Error creating reservation")
		if err.Error() == "Reservation already exists for the specified dates and accommodation." {
			s.logger.Errorf("ReservationHandler.CreateReservation : No one else can book accommodation for the reserved dates")
			rw.WriteHeader(http.StatusMethodNotAllowed)
			rw.Write([]byte("No one else can book accommodation for the reserved dates"))
		} else if err.Error() == "Can not reserve a date that does not exist in appointments." {
			s.logger.Errorf("ReservationHandler.CreateReservation : Can not reserve a date that does not exist in appointments")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Can not reserve a date that does not exist in appointments."))
		} else if err.Error() == "Error creating reservation. Cannot create reservation in the past." {
			s.logger.Errorf("ReservationHandler.CreateReservation : Error creating reservation. Cannot create reservation in the past")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error creating reservation. Cannot create reservation in the past."))
		} else {
			s.logger.Errorf("ReservationHandler.CreateReservation : Database exception")
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

		accommodationDetailsEndpoint := fmt.Sprintf("https://%s:%s/%s", accommodationServiceHost, accommodationServicePort, createdReservation.AccommodationId)
		accommodationDetailsResponse, err := s.HTTPSRequestWithouthBody(ctx, tokenString, accommodationDetailsEndpoint, "GET")
		if err != nil {
			s.logger.Errorf("ReservationHandler.CreateReservation : Error fetching accommodation details")
			span.SetStatus(codes.Error, "Error fetching accommodation details")
			return nil, fmt.Errorf("Error fetching accommodation details: %v", err)
		}
		defer accommodationDetailsResponse.Body.Close()

		if accommodationDetailsResponse.StatusCode != http.StatusOK {
			s.logger.Errorf("ReservationHandler.CreateReservation : Error fetching accommodation details")
			span.SetStatus(codes.Error, "Error fetching accommodation details")
			return nil, fmt.Errorf("Error fetching accommodation details. Status code: %d", accommodationDetailsResponse.StatusCode)
		}

		body, err := ioutil.ReadAll(accommodationDetailsResponse.Body)
		if err != nil {
			s.logger.Errorf("ReservationHandler.CreateReservation : Error reading accommodation details response")
			span.SetStatus(codes.Error, "Error reading accommodation details response")
			return nil, fmt.Errorf("Error reading accommodation details response: %v", err)
		}

		var accommodationDetails AccommodationDetails
		err = json.Unmarshal(body, &accommodationDetails)
		if err != nil {
			s.logger.Errorf("ReservationHandler.CreateReservation : Error unmarshaling accommodation details JSON")
			span.SetStatus(codes.Error, "Error unmarshaling accommodation details JSON")
			return nil, fmt.Errorf("Error unmarshaling accommodation details JSON: %v", err)
		}

		return &accommodationDetails, nil
	})

	if breakerErrAccommodation != nil {
		s.logger.Errorf("ReservationHandler.CreateReservation : Circuit breaker error")
		span.SetStatus(codes.Error, "Circuit breaker error")
		log.Printf("Circuit breaker error: %v", breakerErrAccommodation)
		log.Println("Before http.Error")

		rw.WriteHeader(http.StatusServiceUnavailable)

		http.Error(rw, "Error getting accommodation service", http.StatusServiceUnavailable)

		log.Println("After http.Error")

		err := s.reservationRepo.DeleteReservation(ctx, createdReservationID)
		if err != nil {
			s.logger.Errorf("ReservationHandler.CreateReservation : Error deleting reservation after circuit breaker error")
			span.SetStatus(codes.Error, "Error deleting reservation after circuit breaker error")
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

		notificationServiceEndpoint := fmt.Sprintf("https://%s:%s/", notificationServiceHost, notificationServicePort)
		responseUser, err := s.HTTPSRequestWithBody(ctx, tokenString, notificationServiceEndpoint, "POST", requestBody)
		if err != nil {
			s.logger.Errorf("ReservationHandler.CreateReservation : Error fetching notification service")
			span.SetStatus(codes.Error, "Error fetching notification service")
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
		s.logger.Errorf("ReservationHandler.CreateReservation : Circuit breaker error")
		span.SetStatus(codes.Error, "Circuit breaker error")
		log.Printf("Circuit breaker error: %v", breakerErrNotification)
		log.Println("Before http.Error")

		rw.WriteHeader(http.StatusServiceUnavailable)

		http.Error(rw, "Error getting notification service", http.StatusServiceUnavailable)

		log.Println("After http.Error")

		err := s.reservationRepo.DeleteReservation(ctx, createdReservationID)
		if err != nil {
			s.logger.Errorf("ReservationHandler.CreateReservation : Error deleting reservation after circuit breaker error")
			span.SetStatus(codes.Error, "Error deleting reservation after circuit breaker error")
			log.Printf("Error deleting reservation after circuit breaker error: %v", err)
		}

		return
	}

	s.logger.Println("Code after circuit breaker execution")

	if resultNotification != nil {

		fmt.Println("Received meaningful data:", resultNotification)
	}
	s.logger.Infoln("ReservationHandler.CreateReservation : CreateReservation finished")
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

	s.logger.Infoln("ReservationHandler.CancelReservation : CancelReservation endpoint reached")

	bearer := h.Header.Get("Authorization")
	if bearer == "" {
		s.logger.Errorf("ReservationHandler.CancelReservation : Authorization header missing")
		log.Println("Authorization header missing")
		span.AddEvent("Authorization header missing")
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bearerToken := strings.Split(bearer, "Bearer ")
	if len(bearerToken) != 2 {
		s.logger.Errorf("ReservationHandler.CancelReservation : Malformed Authorization header")
		log.Println("Malformed Authorization header")
		span.AddEvent("Malformed Authorization header")
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := bearerToken[1]
	log.Printf("Token: %s\n", tokenString)

	vars := mux.Vars(h)
	reservationID := vars["id"]

	reservation, err := s.reservationRepo.GetReservationByID(ctx, reservationID)
	if err != nil {
		s.logger.Errorf("ReservationHandler.CancelReservation : Error retrieving reservation")
		span.SetStatus(codes.Error, "Error retrieving reservation.")
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Error retrieving reservation."))
		return
	}

	// Circuit breaker for accommodation service
	resultAccommodation, breakerErrAccommodation := s.cb.Execute(func() (interface{}, error) {
		accommodationDetailsEndpoint := fmt.Sprintf("https://%s:%s/%s", accommodationServiceHost, accommodationServicePort, reservation.AccommodationId)
		accommodationDetailsResponse, err := s.HTTPSRequestWithouthBody(ctx, tokenString, accommodationDetailsEndpoint, "GET")
		if err != nil {
			s.logger.Errorf("ReservationHandler.CancelReservation : Error fetching accommodation details")
			span.SetStatus(codes.Error, "Error fetching accommodation details")
			return nil, fmt.Errorf("Error fetching accommodation details: %v", err)
		}
		defer accommodationDetailsResponse.Body.Close()

		if accommodationDetailsResponse.StatusCode != http.StatusOK {
			s.logger.Errorf("ReservationHandler.CancelReservation : Error fetching accommodation details")
			span.SetStatus(codes.Error, "Error fetching accommodation details")
			return nil, fmt.Errorf("Error fetching accommodation details. Status code: %d", accommodationDetailsResponse.StatusCode)
		}

		body, err := ioutil.ReadAll(accommodationDetailsResponse.Body)
		if err != nil {
			s.logger.Errorf("ReservationHandler.CancelReservation : Error reading accommodation details response")
			span.SetStatus(codes.Error, "Error reading accommodation details response")
			return nil, fmt.Errorf("Error reading accommodation details response: %v", err)
		}

		var accommodationDetails AccommodationDetails
		err = json.Unmarshal(body, &accommodationDetails)
		if err != nil {
			s.logger.Errorf("ReservationHandler.CancelReservation : Error unmarshaling accommodation details JSON")
			span.SetStatus(codes.Error, "Error unmarshaling accommodation details JSON")
			return nil, fmt.Errorf("Error unmarshaling accommodation details JSON: %v", err)
		}

		return &accommodationDetails, nil
	})

	if breakerErrAccommodation != nil {
		s.logger.Errorf("ReservationHandler.CancelReservation : Circuit breaker error")
		span.SetStatus(codes.Error, "Circuit breaker error")
		log.Printf("Circuit breaker error: %v", breakerErrAccommodation)
		log.Println("Before http.Error")

		rw.WriteHeader(http.StatusServiceUnavailable)

		http.Error(rw, "Error getting accommodation service", http.StatusServiceUnavailable)

		log.Println("After http.Error")

		return
	}

	accommodationDetails := resultAccommodation.(*AccommodationDetails)

	fmt.Println("OwnerId:", accommodationDetails.OwnerId)
	fmt.Println("Name:", accommodationDetails.Name)

	err = s.reservationRepo.CancelReservation(ctx, reservationID, tokenString)
	if err != nil {
		s.logger.Errorf("ReservationHandler.CancelReservation : Error canceling reservation")
		span.SetStatus(codes.Error, "Error canceling reservation")
		if err.Error() == "Can not cancel reservation. You can only cancel it before it starts." {
			s.logger.Errorf("ReservationHandler.CancelReservation : Can not cancel reservation. You can only cancel it before it starts.")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Can not cancel reservation. You can only cancel it before it starts."))
		} else {
			s.logger.Errorf("ReservationHandler.CancelReservation : Error cancelling reservation")
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

		notificationServiceEndpoint := fmt.Sprintf("https://%s:%s/", notificationServiceHost, notificationServicePort)
		responseUser, err := s.HTTPSRequestWithBody(ctx, tokenString, notificationServiceEndpoint, "POST", requestBody)
		if err != nil {
			s.logger.Errorf("ReservationHandler.CancelReservation : Error fetching notification service")
			span.SetStatus(codes.Error, "Error fetching notification service")
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
		s.logger.Errorf("ReservationHandler.CancelReservation : Circuit breaker error")
		span.SetStatus(codes.Error, "Circuit breaker error")
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

	s.logger.Infof("ReservationHandler.CancelReservation : Data of cancelled reservation: %+v", reservationID)
	s.logger.Infoln("ReservationHandler.CancelReservation : CancelReservation success")
	rw.WriteHeader(http.StatusOK)
	s.logger.Print("Reservation cancelled succesfully")

}

func (s *ReservationHandler) GetReservationByUser(rw http.ResponseWriter, h *http.Request) {
	ctx, span := s.tracer.Start(h.Context(), "ReservationHandler.GetReservationByUser")
	defer span.End()

	s.logger.Infoln("ReservationHandler.GetReservationByUser : GetReservationByUser endpoint reached")

	bearer := h.Header.Get("Authorization")
	if bearer == "" {
		s.logger.Errorf("ReservationHandler.GetReservationByUser : Authorization header missing")
		span.SetStatus(codes.Error, "Authorization header missing")
		log.Println("Authorization header missing")
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bearerToken := strings.Split(bearer, "Bearer ")
	if len(bearerToken) != 2 {
		s.logger.Errorf("ReservationHandler.GetReservationByUser : Malformed header missing")
		span.SetStatus(codes.Error, "Malformed header missing")
		log.Println("Malformed Authorization header")
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := bearerToken[1]
	log.Printf("Token: %s\n", tokenString)

	token, err := jwt.Parse([]byte(tokenString), verifier)
	if err != nil {
		s.logger.Errorf("ReservationHandler.GetReservationByUser : Token parsing error")
		span.SetStatus(codes.Error, "Token parsing error")
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
		userID, statusCode, err := s.getUserIDFromUserService(ctx, username, tokenString)
		return map[string]interface{}{"userID": userID, "statusCode": statusCode, "err": err}, err
	})

	if breakerErr != nil {
		s.logger.Errorf("ReservationHandler.GetReservationByUser : Service Unavailable")
		span.SetStatus(codes.Error, "Service Unavailable")
		log.Println("Circuit breaker open:", breakerErr)
		http.Error(rw, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		s.logger.Errorf("ReservationHandler.GetReservationByUser : Internal server error: Unexpected result type")
		span.SetStatus(codes.Error, "Internal server error: Unexpected result type")
		log.Println("Internal server error: Unexpected result type")
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID, ok := resultMap["userID"].(string)
	if !ok {
		s.logger.Errorf("ReservationHandler.GetReservationByUser : Internal server error: User ID not found in the response")
		span.SetStatus(codes.Error, "Internal server error: User ID not found in the response")
		log.Println("Internal server error: User ID not found in the response")
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}

	statusCode, ok := resultMap["statusCode"].(int)
	if !ok {
		s.logger.Errorf("ReservationHandler.GetReservationByUser : Internal server error: Status code not found in the response")
		span.SetStatus(codes.Error, "Internal server error: Status code not found in the response")
		log.Println("Internal server error: Status code not found in the response")
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err, ok := resultMap["err"].(error); ok && err != nil {
		s.logger.Errorf("ReservationHandler.GetReservationByUser : Error from user service")
		span.SetStatus(codes.Error, "Error from user service")
		log.Println("Error from user service:", err)
		http.Error(rw, err.Error(), statusCode)
		return
	}

	reservationByUser, err := s.reservationRepo.GetReservationByUser(ctx, userID)
	if err != nil {
		s.logger.Errorf("ReservationHandler.GetReservationByUser : Database exception")
		span.SetStatus(codes.Error, "Error getting reservations")
		http.Error(rw, "Error getting reservations", http.StatusInternalServerError)
		return
	}

	if reservationByUser == nil {
		s.logger.Errorf("ReservationHandler.GetReservationByUser : Reservations not found")
		span.SetStatus(codes.Error, "Reservation not found")
		http.Error(rw, "Reservations not found", http.StatusNotFound)
		return
	}

	err = reservationByUser.ToJSON(rw)
	if err != nil {
		s.logger.Errorf("ReservationHandler.GetReservationByUser : Unable to convert to json")
		span.SetStatus(codes.Error, "Unable to convert to json")
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		return
	}
}

func (s *ReservationHandler) getUserIDFromUserService(ctx context.Context, username interface{}, token string) (string, int, error) {
	ctx, span := s.tracer.Start(ctx, "ReservationHandler.getUserIDFromUserService")
	defer span.End()

	s.logger.Infoln("ReservationHandler.getUserIDFromUserService : GetReservationByUser endpoint reached")

	userServiceEndpoint := fmt.Sprintf("https://%s:%s/getOne/%s", userServiceHost, userServicePort, username)
	response, err := s.HTTPSRequestWithouthBody(ctx, token, userServiceEndpoint, "GET")
	if err != nil {
		s.logger.Errorf("ReservationHandler.getUserIDFromUserService : Interval server error")
		span.SetStatus(codes.Error, "Interval server error")
		return "", http.StatusInternalServerError, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		s.logger.Errorf("ReservationHandler.getUserIDFromUserService : User not found in database")
		span.SetStatus(codes.Error, "User not found in database")
		return "", response.StatusCode, fmt.Errorf("User not found in database")
	}

	var user map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&user); err != nil {
		s.logger.Errorf("ReservationHandler.getUserIDFromUserService : Error decoding user response")
		span.SetStatus(codes.Error, "Error decoding user response")
		return "", http.StatusInternalServerError, err
	}

	userID, ok := user["id"].(string)
	if !ok {
		s.logger.Errorf("ReservationHandler.getUserIDFromUserService : User ID not found in the response")
		span.SetStatus(codes.Error, "User ID not found in the response")
		return "", http.StatusInternalServerError, fmt.Errorf("User ID not found in the response")
	}

	return userID, http.StatusOK, nil
}

func (s *ReservationHandler) GetReservationByAccommodation(rw http.ResponseWriter, h *http.Request) {
	ctx, span := s.tracer.Start(h.Context(), "ReservationHandler.GetReservationByAccommodation")
	defer span.End()

	s.logger.Infoln("ReservationHandler.GetReservationByAccommodation : GetReservationByUser endpoint reached")

	vars := mux.Vars(h)
	id := vars["id"]

	reservationByUser, err := s.reservationRepo.GetReservationByAccommodation(ctx, id)
	if err != nil {
		s.logger.Errorf("ReservationHandler.getUserIDFromUserService : Database exception")
		span.SetStatus(codes.Error, "Error getting reservations by user")
	}

	if reservationByUser == nil {
		return
	}

	err = reservationByUser.ToJSON(rw)
	if err != nil {
		s.logger.Errorf("ReservationHandler.GetReservationByAccommodation : Unable to convert to json")
		span.SetStatus(codes.Error, "Unable to convert to json")
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
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

	s.logger.Infoln("ReservationHandler.CheckReservation : CheckReservation endpoint reached")

	var requestBody struct {
		AccommodationID string   `json:"accommodationId"`
		Available       []string `json:"available"`
	}

	err := json.NewDecoder(h.Body).Decode(&requestBody)
	if err != nil {
		s.logger.Errorf("ReservationHandler.CheckReservation : Error decoding JSON")
		span.SetStatus(codes.Error, "Unable to decode JSON")
		http.Error(rw, "Unable to decode JSON", http.StatusBadRequest)
		return
	}

	// Pretvori stringove u time.Time
	var available []time.Time
	for _, t := range requestBody.Available {
		parsedTime, err := time.Parse(time.RFC3339, t)
		if err != nil {
			s.logger.Errorf("ReservationHandler.CheckReservation : Error parsing time")
			span.SetStatus(codes.Error, "Invalid time format in JSON")
			http.Error(rw, "Invalid time format in JSON", http.StatusBadRequest)
			return
		}
		available = append(available, parsedTime)
	}
	fmt.Println(available, "Available check reservation")

	exists, err := s.reservationRepo.ReservationExistsForAppointment(ctx, requestBody.AccommodationID, available)
	if err != nil {
		s.logger.Errorf("ReservationHandler.CheckReservation : Error checking reservation")
		span.SetStatus(codes.Error, "Error checking reservation")
		http.Error(rw, "Error checking reservation", http.StatusInternalServerError)
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

	s.logger.Infoln("ReservationHandler.CheckHostReservations : CheckHostReservations endpoint reached")

	vars := mux.Vars(h)
	userID := vars["id"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		s.logger.Errorf("ReservationHandler.CheckHostReservations : Error extracting Bearer token")
		span.SetStatus(codes.Error, "Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	hasReservations, err := s.reservationRepo.HasReservationsForHost(ctx, userID, authToken)
	if err != nil {
		s.logger.Errorf("ReservationHandler.CheckHostReservations : Error checking host reservations")
		span.SetStatus(codes.Error, "Error checking host reservations")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(rw).Encode(hasReservations); err != nil {
		s.logger.Errorf("ReservationHandler.CheckHostReservations : Error encoding JSON response")
		span.SetStatus(codes.Error, "Error encoding JSON response")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (rh *ReservationHandler) CheckUserPastReservations(w http.ResponseWriter, r *http.Request) {
	ctx, span := rh.tracer.Start(r.Context(), "ReservationHandler.CheckUserPastReservations")
	defer span.End()

	rh.logger.Infoln("ReservationHandler.CheckUserPastReservations : CheckUserPastReservations endpoint reached")

	userID := mux.Vars(r)["id"]
	hostID := mux.Vars(r)["hostId"]

	authHeader := r.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		rh.logger.Errorf("ReservationHandler.CheckUserPastReservations : Error extracting Bearer token")
		span.SetStatus(codes.Error, "Error extracting Bearer token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	hasPastReservations, err := rh.reservationRepo.CheckUserPastReservations(ctx, userID, hostID, authToken)
	if err != nil {
		rh.logger.Errorf("ReservationHandler.CheckUserPastReservations : Error checking user past reservations")
		span.SetStatus(codes.Error, "Error checking user past reservations")
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

	rh.logger.Infoln("ReservationHandler.CheckUserPastReservationsInAccommodation : CheckUserPastReservationsInAccommodation endpoint reached")

	userID := mux.Vars(r)["id"]
	accommodationID := mux.Vars(r)["accommodationId"]

	authHeader := r.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		rh.logger.Errorf("ReservationHandler.CheckUserPastReservationsInAccommodation : Error extracting Bearer token")
		span.SetStatus(codes.Error, "Error extracting Bearer token")
		rh.logger.Println("Error extracting Bearer token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	hasPastReservations, err := rh.reservationRepo.CheckUserPastReservationsInAccommodation(ctx, userID, accommodationID)
	if err != nil {
		rh.logger.Errorf("ReservationHandler.CheckUserPastReservationsInAccommodation : Error checking user past reservations")
		span.SetStatus(codes.Error, "Error checking user past reservations")
		log.Println("Error checking user past reservations:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Println(hasPastReservations)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(hasPastReservations)
}

func (s *ReservationHandler) CheckCancellationRateBelowThreshold(rw http.ResponseWriter, h *http.Request) {
	ctx, span := s.tracer.Start(h.Context(), "ReservationHandler.CheckCancellationRateBelowThreshold")
	defer span.End()

	s.logger.Infoln("ReservationHandler.CheckCancellationRateBelowThreshold : CheckCancellationRateBelowThreshold endpoint reached")

	vars := mux.Vars(h)
	userID := vars["id"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		s.logger.Errorf("ReservationHandler.CheckCancellationRateBelowThreshold : Error extracting Bearer token")
		span.SetStatus(codes.Error, "Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	isBelowThreshold, err := s.reservationRepo.IsCancellationRateBelowThreshold(ctx, userID, authToken)
	if err != nil {
		s.logger.Errorf("ReservationHandler.CheckCancellationRateBelowThreshold : Error checking cancellation rate")
		span.SetStatus(codes.Error, "Error checking cancellation rate")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := map[string]bool{"isBelowThreshold": isBelowThreshold}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(rw).Encode(response); err != nil {
		s.logger.Errorf("ReservationHandler.CheckCancellationRateBelowThreshold : Error encoding JSON response")
		span.SetStatus(codes.Error, "Error encoding JSON response")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *ReservationHandler) HasEnoughCompletedReservations(rw http.ResponseWriter, h *http.Request) {
	ctx, span := s.tracer.Start(h.Context(), "ReservationHandler.HasEnoughCompletedReservations")
	defer span.End()

	s.logger.Infoln("ReservationHandler.HasEnoughCompletedReservations : HasEnoughCompletedReservations endpoint reached")

	// Extract user ID from request or any other necessary information
	vars := mux.Vars(h)
	userID := vars["id"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		s.logger.Errorf("ReservationHandler.HasEnoughCompletedReservations : Error extracting Bearer token")
		span.SetStatus(codes.Error, "Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Call the repository method to check if the user has enough completed reservations
	hasEnoughReservations, err := s.reservationRepo.HasEnoughCompletedReservations(ctx, userID, authToken)
	if err != nil {
		s.logger.Errorf("ReservationHandler.HasEnoughCompletedReservations : Error checking completed reservations")
		span.SetStatus(codes.Error, "Error checking completed reservations")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Respond with the result
	response := map[string]bool{"hasEnoughReservations": hasEnoughReservations}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(rw).Encode(response); err != nil {
		s.logger.Errorf("ReservationHandler.HasEnoughCompletedReservations : Error encoding JSON response")
		span.SetStatus(codes.Error, "Error encoding JSON response")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *ReservationHandler) CheckReservationsMoreThan50Days(rw http.ResponseWriter, h *http.Request) {
	ctx, span := s.tracer.Start(h.Context(), "ReservationHandler.CheckReservationsMoreThan50Days")
	defer span.End()

	s.logger.Infoln("ReservationHandler.CheckReservationsMoreThan50Days : CheckReservationsMoreThan50Days endpoint reached")

	vars := mux.Vars(h)
	userID := vars["id"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		s.logger.Errorf("ReservationHandler.CheckReservationsMoreThan50Days : Error extracting Bearer token")
		span.SetStatus(codes.Error, "Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	hasMoreThan50Days, err := s.reservationRepo.HasReservationsMoreThan50Days(ctx, userID, authToken)
	if err != nil {
		s.logger.Errorf("ReservationHandler.CheckReservationsMoreThan50Days : Error checking reservations more than 50 days")
		span.SetStatus(codes.Error, "Error checking reservations more than 50 days")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Respond with the result
	response := map[string]bool{"hasMoreThan50Days": hasMoreThan50Days}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(rw).Encode(response); err != nil {
		s.logger.Errorf("ReservationHandler.CheckReservationsMoreThan50Days : Error encoding JSON response")
		span.SetStatus(codes.Error, "Error encoding JSON response")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
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

func (s *ReservationHandler) HTTPSRequestWithBody(ctx context.Context, token string, url string, method string, requestBody interface{}) (*http.Response, error) {
	clientCertPath := "ca-cert.pem"

	clientCaCert, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(clientCaCert)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		CurvePreferences: []tls.CurveID{tls.CurveP521,
			tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *ReservationHandler) HTTPSRequestWithouthBody(ctx context.Context, token string, url string, method string) (*http.Response, error) {
	clientCertPath := "ca-cert.pem"

	clientCaCert, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(clientCaCert)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		CurvePreferences: []tls.CurveID{tls.CurveP521,
			tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return resp, nil
}
