package data

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	// NoSQL: module containing Cassandra api client
	"github.com/gocql/gocql"
)

var (
	reservationServiceHost   = os.Getenv("RESERVATIONS_SERVICE_HOST")
	reservationServicePort   = os.Getenv("RESERVATIONS_SERVICE_PORT")
	accommodationServiceHost = os.Getenv("ACCOMMODATIONS_SERVICE_HOST")
	accommodationServicePort = os.Getenv("ACCOMMODATIONS_SERVICE_PORT")
	usersServiceHost         = os.Getenv("USER_SERVICE_HOST")
	usersServicePort         = os.Getenv("USER_SERVICE_PORT")
)

type ReservationRepo struct {
	session *gocql.Session
	logger  *log.Logger
	client  *http.Client
	tracer  trace.Tracer
}

func NewReservationRepo(tracer trace.Tracer, logger *log.Logger) (*ReservationRepo, error) {

	db := os.Getenv("RESERVATIONS_DB_HOST")

	// Connect to default keyspace
	cluster := gocql.NewCluster(db)
	cluster.Keyspace = "system"
	session, err := cluster.CreateSession()
	if err != nil {
		logger.Println(err)
		return nil, err
	}

	// Create 'reservation' keyspace
	err = session.Query(
		fmt.Sprintf(`CREATE KEYSPACE IF NOT EXISTS %s
					WITH replication = {
						'class' : 'SimpleStrategy',
						'replication_factor' : %d
					}`, "reservation", 1)).Exec()
	if err != nil {
		logger.Println(err)
	}
	session.Close()

	// Connect to reservation keyspace
	cluster.Keyspace = "reservation"
	cluster.Consistency = gocql.One
	session, err = cluster.CreateSession()
	if err != nil {
		logger.Println(err)
		return nil, err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        30,
			MaxIdleConnsPerHost: 30,
			MaxConnsPerHost:     30,
		},
	}

	// Return repository with logger and DB session
	return &ReservationRepo{
		session: session,
		logger:  logger,
		client:  httpClient,
		tracer:  tracer,
	}, nil
}

// Disconnect from database
func (sr *ReservationRepo) CloseSession() {
	sr.session.Close()
}

// Create tables
func (sr *ReservationRepo) CreateTables() {

	err := sr.session.Query(
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s 
					(by_userId text,reservation_id UUID, periodd LIST<TIMESTAMP>, accommodation_id text, price int, canceled boolean,
					PRIMARY KEY ((by_userId), reservation_id)) 
					WITH CLUSTERING ORDER BY (reservation_id ASC)`, "reservation_by_user")).Exec()
	if err != nil {
		sr.logger.Println(err)
	}

	err = sr.session.Query(
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s 
					(by_userId text,reservation_id UUID, periodd LIST<TIMESTAMP>, accommodation_id text, price int, canceled boolean,
					PRIMARY KEY ((accommodation_id), reservation_id)) 
					WITH CLUSTERING ORDER BY (reservation_id ASC)`, "reservation_by_accommodation")).Exec()
	if err != nil {
		sr.logger.Println(err)
	}

}

// cassandra
func (sr *ReservationRepo) InsertReservation(ctx context.Context, reservation *Reservation, token string) (*Reservation, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.InsertReservation")
	defer span.End()

	exists, err := sr.ReservationExistsForAppointment(ctx, reservation.AccommodationId, reservation.Period)
	if err != nil {
		span.SetStatus(codes.Error, "Error reservation exists for appointment")
		return nil, err
	}
	if exists {
		span.SetStatus(codes.Error, "Reservation already exists for the specified dates and accommodation.")
		return nil, errors.New("Reservation already exists for the specified dates and accommodation.")
	}

	reservationId, _ := gocql.RandomUUID()

	appointments, err := sr.getAppointmentsByAccommodation(ctx, reservation.AccommodationId, token)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting appointments")
		return nil, err
	}

	for _, reservedDate := range reservation.Period {
		dateFound := false

		for _, appointment := range appointments {
			for _, availableDate := range appointment.Available {
				if reservedDate.Equal(availableDate) {
					dateFound = true
					break
				}
			}
		}

		if !dateFound {
			span.SetStatus(codes.Error, "Can not reserve a date that does not exist in appointments.")
			return nil, errors.New("Can not reserve a date that does not exist in appointments.")
		}
	}

	for _, newReservation := range reservation.Period {
		if time.Now().After(newReservation) {
			span.SetStatus(codes.Error, "Error creating reservation. Cannot create reservation in the past.")
			return nil, errors.New("Error creating reservation. Cannot create reservation in the past.")
		}
	}

	var sum int

	for _, appointment := range appointments {
		for _, date := range appointment.Available {
			for _, reservedDate := range reservation.Period {
				if date.Equal(reservedDate) {
					if appointment.PricePerGuest != 0 {
						sum = sum + appointment.PricePerGuest
					} else {
						sum = sum + appointment.PricePerAccommodation
					}

				}
			}
		}
	}

	reservation.Price = sum
	reservation.Canceled = false

	err = sr.session.Query(
		`INSERT INTO reservation_by_user (by_userId, reservation_id, periodd, accommodation_id, price, canceled) 
        VALUES (?, ?, ?, ?, ?, ?)`,
		reservation.ByUserId, reservationId, reservation.Period, reservation.AccommodationId, reservation.Price, reservation.Canceled).Exec()
	if err != nil {
		sr.logger.Println(err)
		return nil, err
	}

	err = sr.session.Query(
		`INSERT INTO reservation_by_accommodation (by_userId, reservation_id, periodd, accommodation_id, price, canceled) 
        VALUES (?, ?, ?, ?, ?, ?)`,
		reservation.ByUserId, reservationId, reservation.Period, reservation.AccommodationId, reservation.Price, reservation.Canceled).Exec()
	if err != nil {
		span.SetStatus(codes.Error, "Error insert reservation")
		sr.logger.Println(err)
		return nil, err
	}

	createdReservation := &Reservation{
		ID:              reservationId,
		ByUserId:        reservation.ByUserId,
		Period:          reservation.Period,
		AccommodationId: reservation.AccommodationId,
		Price:           reservation.Price,
		Canceled:        reservation.Canceled,
	}

	accommodationEndpoint := fmt.Sprintf("http://%s:%s/%s", accommodationServiceHost, accommodationServicePort, reservation.AccommodationId)
	accommodationRequest, err := http.NewRequest("GET", accommodationEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(accommodationRequest.Header))
	if err != nil {
		span.SetStatus(codes.Error, "Error creating accommodation request")
		fmt.Println("Error creating accommodation request:", err)
		return nil, err
	}

	accommodationRequest.Header.Set("Authorization", "Bearer "+token)

	accommodationResponse, err := http.DefaultClient.Do(accommodationRequest)
	if err != nil {
		span.SetStatus(codes.Error, "Error sending accommodation request")
		fmt.Println("Error sending accommodation request:", err)
		return nil, err
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Accommodation service returned an error")
		fmt.Println("Accommodation service returned an error:", accommodationResponse.Status)
		return nil, errors.New("Accommodation service returned an error")
	}

	type AccommodationResponse struct {
		OwnerID string `json:"ownerId"`
	}

	var response AccommodationResponse

	//err = responseToType(accommodationResponse.Body, accommodations)
	err = json.NewDecoder(accommodationResponse.Body).Decode(&response)
	if err != nil {
		span.SetStatus(codes.Error, "Error decoding accommodation response")
		fmt.Println("Error decoding accommodation response:", err)
		return nil, err
	}

	defer accommodationResponse.Body.Close()

	usersEndpoint := fmt.Sprintf("http://%s:%s/isHighlighted/%s", usersServiceHost, usersServicePort, response.OwnerID)
	usersRequest, err := http.NewRequest("GET", usersEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(usersRequest.Header))
	if err != nil {
		span.SetStatus(codes.Error, "Error creating users request")
		fmt.Println("Error creating users request:", err)
		return nil, err
	}

	usersRequest.Header.Set("Authorization", "Bearer "+token)

	usersResponse, err := http.DefaultClient.Do(usersRequest)
	if err != nil {
		span.SetStatus(codes.Error, "Error sending users request")
		fmt.Println("Error sending users request:", err)
		return nil, err
	}

	if usersResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Users service returned an error")
		fmt.Println("Users service returned an error:", usersResponse.Status)
		return nil, errors.New("Users service returned an error")
	}

	var response2 bool

	err = json.NewDecoder(usersResponse.Body).Decode(&response2)
	if err != nil {
		span.SetStatus(codes.Error, "Error decoding users response")
		fmt.Println("Error decoding users response:", err)
		return nil, err
	}

	defer usersResponse.Body.Close()

	return createdReservation, nil
}

func (sr *ReservationRepo) ReservationExistsForAppointment(ctx context.Context, accommodationID string, available []time.Time) (bool, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.ReservationExistsForAppointment")
	defer span.End()

	allReservations, err := sr.GetReservationByAccommodation(ctx, accommodationID)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting reservations")
		return false, err
	}

	for _, reservation := range allReservations {
		for _, date := range reservation.Period {
			for _, availableDate := range available {
				if date.Equal(availableDate) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func (sr *ReservationRepo) HasReservationsForHost(ctx context.Context, userID string, authToken string) (bool, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.HasReservationsForHost")
	defer span.End()

	accommodationEndpoint := fmt.Sprintf("https://%s:%s/owner/%s", accommodationServiceHost, accommodationServicePort, userID)
	accommodationResponse, err := sr.HTTPSRequestWithouthBody(ctx, authToken, accommodationEndpoint, "GET")
	if err != nil {
		span.SetStatus(codes.Error, "Error sending accommodation request")
		sr.logger.Println("Error sending accommodation request:", err)
		return false, err
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Accommodation service returned an error")
		sr.logger.Println("Accommodation service returned an error:", accommodationResponse.Status)
		return false, errors.New("Accommodation service returned an error")
	}

	var accommodations []primitive.ObjectID

	err = json.NewDecoder(accommodationResponse.Body).Decode(&accommodations)
	if err != nil {
		span.SetStatus(codes.Error, "Error decoding accommodation response")
		sr.logger.Println("Error decoding accommodation response:", err)
		return false, err
	}

	defer accommodationResponse.Body.Close()
	for _, accommodationID := range accommodations {
		hasReservations, err := sr.HasReservationsForAccommodation(ctx, accommodationID)
		if err != nil {
			span.SetStatus(codes.Error, "Error checking reservations for accommodation")
			sr.logger.Println(err)
			return false, err
		}

		if hasReservations {
			return true, nil
		}
	}

	return false, nil
}

func (sr *ReservationRepo) GetCancelledReservationsByHost(ctx context.Context, userID string, authToken string) (Reservations, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.GetCancelledReservationsByHost")
	defer span.End()

	accommodationEndpoint := fmt.Sprintf("http://%s:%s/owner/%s", accommodationServiceHost, accommodationServicePort, userID)
	accommodationRequest, err := http.NewRequest("GET", accommodationEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(accommodationRequest.Header))
	if err != nil {
		span.SetStatus(codes.Error, "Error creating accommodation request")
		sr.logger.Println("Error creating accommodation request:", err)
		return nil, err
	}

	accommodationRequest.Header.Set("Authorization", "Bearer "+authToken)

	accommodationResponse, err := http.DefaultClient.Do(accommodationRequest)
	if err != nil {
		span.SetStatus(codes.Error, "Error sending accommodation request")
		sr.logger.Println("Error sending accommodation request:", err)
		return nil, err
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Accommodation service returned an error")
		sr.logger.Println("Accommodation service returned an error:", accommodationResponse.Status)
		return nil, errors.New("Accommodation service returned an error")
	}

	var accommodations []primitive.ObjectID

	//err = responseToType(accommodationResponse.Body, accommodations)
	err = json.NewDecoder(accommodationResponse.Body).Decode(&accommodations)
	if err != nil {
		span.SetStatus(codes.Error, "Error decoding accommodation response")
		sr.logger.Println("Error decoding accommodation response:", err)
		return nil, err
	}

	defer accommodationResponse.Body.Close()

	var cancelledReservations Reservations
	for _, accommodationID := range accommodations {
		reservations, err := sr.GetReservationByAccommodation(ctx, accommodationID.Hex())
		if err != nil {
			span.SetStatus(codes.Error, "Error getting reservations for accommodation")
			sr.logger.Println(err)
			return nil, err
		}

		for _, reservation := range reservations {
			if reservation.Canceled {
				cancelledReservations = append(cancelledReservations, reservation)
			}
		}
	}

	return cancelledReservations, nil
}

func (sr *ReservationRepo) GetAllReservationsByHost(ctx context.Context, userID string, authToken string) (Reservations, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.GetCancelledReservationsByHost")
	defer span.End()

	accommodationEndpoint := fmt.Sprintf("http://%s:%s/owner/%s", accommodationServiceHost, accommodationServicePort, userID)
	accommodationRequest, err := http.NewRequest("GET", accommodationEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(accommodationRequest.Header))
	if err != nil {
		span.SetStatus(codes.Error, "Error creating accommodation request")
		sr.logger.Println("Error creating accommodation request:", err)
		return nil, err
	}

	accommodationRequest.Header.Set("Authorization", "Bearer "+authToken)

	accommodationResponse, err := http.DefaultClient.Do(accommodationRequest)
	if err != nil {
		span.SetStatus(codes.Error, "Error sending accommodation request")
		sr.logger.Println("Error sending accommodation request:", err)
		return nil, err
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Accommodation service returned an error")
		sr.logger.Println("Accommodation service returned an error:", accommodationResponse.Status)
		return nil, errors.New("Accommodation service returned an error")
	}

	var accommodations []primitive.ObjectID

	//err = responseToType(accommodationResponse.Body, accommodations)
	err = json.NewDecoder(accommodationResponse.Body).Decode(&accommodations)
	if err != nil {
		span.SetStatus(codes.Error, "Error decoding accommodation response")
		sr.logger.Println("Error decoding accommodation response:", err)
		return nil, err
	}

	defer accommodationResponse.Body.Close()

	var reservations Reservations
	for _, accommodationID := range accommodations {
		reservationsByAccommodation, err := sr.GetReservationByAccommodation(ctx, accommodationID.Hex())
		if err != nil {
			span.SetStatus(codes.Error, "Error getting reservations for accommodation")
			sr.logger.Println(err)
			return nil, err
		}

		for _, reservation := range reservationsByAccommodation {
			//if !reservation.Canceled {
			reservations = append(reservations, reservation)
			//}
		}
	}

	return reservations, nil
}

func (sr *ReservationRepo) GetReservationsByHost(ctx context.Context, userID string, authToken string) (Reservations, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.GetCancelledReservationsByHost")
	defer span.End()

	accommodationEndpoint := fmt.Sprintf("http://%s:%s/owner/%s", accommodationServiceHost, accommodationServicePort, userID)
	accommodationRequest, err := http.NewRequest("GET", accommodationEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(accommodationRequest.Header))
	if err != nil {
		span.SetStatus(codes.Error, "Error creating accommodation request")
		sr.logger.Println("Error creating accommodation request:", err)
		return nil, err
	}

	accommodationRequest.Header.Set("Authorization", "Bearer "+authToken)

	accommodationResponse, err := http.DefaultClient.Do(accommodationRequest)
	if err != nil {
		span.SetStatus(codes.Error, "Error sending accommodation request")
		sr.logger.Println("Error sending accommodation request:", err)
		return nil, err
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Accommodation service returned an error")
		sr.logger.Println("Accommodation service returned an error:", accommodationResponse.Status)
		return nil, errors.New("Accommodation service returned an error")
	}

	var accommodations []primitive.ObjectID

	//err = responseToType(accommodationResponse.Body, accommodations)
	err = json.NewDecoder(accommodationResponse.Body).Decode(&accommodations)
	if err != nil {
		span.SetStatus(codes.Error, "Error decoding accommodation response")
		sr.logger.Println("Error decoding accommodation response:", err)
		return nil, err
	}

	defer accommodationResponse.Body.Close()

	var reservations Reservations
	for _, accommodationID := range accommodations {
		reservationsByAccommodation, err := sr.GetReservationByAccommodation(ctx, accommodationID.Hex())
		if err != nil {
			span.SetStatus(codes.Error, "Error getting reservations for accommodation")
			sr.logger.Println(err)
			return nil, err
		}

		for _, reservation := range reservationsByAccommodation {
			if !reservation.Canceled {
				reservations = append(reservations, reservation)
			}
		}
	}

	return reservations, nil
}

func (sr *ReservationRepo) HasReservationsForAccommodation(ctx context.Context, accommodationID primitive.ObjectID) (bool, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.HasReservationsForAccommodation")
	defer span.End()

	scanner := sr.session.Query(
		`SELECT COUNT(*) FROM reservation_by_accommodation WHERE accommodation_id = ?`, accommodationID.Hex()).
		Iter().Scanner()

	var count int
	if scanner.Next() {
		err := scanner.Scan(&count)
		if err != nil {
			span.SetStatus(codes.Error, "Error checking reservations for accommodation")
			sr.logger.Println(err)
			return false, err
		}
	} else {
		return false, nil
	}

	if err := scanner.Err(); err != nil {
		span.SetStatus(codes.Error, "Error checking reservations for accommodation")
		sr.logger.Println(err)
		return false, err
	}
	return count > 0, nil
}

func (sr *ReservationRepo) CheckUserPastReservations(ctx context.Context, userID string, hostID string, token string) (bool, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.CheckUserPastReservations")
	defer span.End()

	accommodationEndpoint := fmt.Sprintf("https://%s:%s/owner/%s", accommodationServiceHost, accommodationServicePort, hostID)
	accommodationResponse, err := sr.HTTPSRequestWithouthBody(ctx, token, accommodationEndpoint, "GET")
	if err != nil {
		span.SetStatus(codes.Error, "Error sending accommodation request")
		sr.logger.Println("Error sending accommodation request:", err)
		return false, err
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Accommodation service returned an error")
		sr.logger.Println("Accommodation service returned an error:", accommodationResponse.Status)
		return false, errors.New("Accommodation service returned an error")
	}

	var accommodations []primitive.ObjectID

	err = json.NewDecoder(accommodationResponse.Body).Decode(&accommodations)
	if err != nil {
		span.SetStatus(codes.Error, "Error decoding accommodation response")
		sr.logger.Println("Error decoding accommodation response:", err)
		return false, err
	}

	defer accommodationResponse.Body.Close()

	reservations, err := sr.GetReservationByUser(ctx, userID)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting reservation by user")
		sr.logger.Println(err)
		return false, err
	}

	currentTime := time.Now()

	for _, reservation := range reservations {
		for _, accommodationId := range accommodations {
			if reservation.AccommodationId == accommodationId.Hex() {
				for _, reservationDate := range reservation.Period {
					if reservationDate.Before(currentTime) {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}

func (sr *ReservationRepo) CheckUserPastReservationsInAccommodation(ctx context.Context, userID string, accommodationID string) (bool, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.CheckUserPastReservationsInAccommodation")
	defer span.End()

	reservations, err := sr.GetReservationByAccommodation(ctx, accommodationID)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting reservations by accommodation")
		sr.logger.Println(err)
		return false, err
	}

	currentTime := time.Now()

	for _, reservation := range reservations {
		if reservation.ByUserId == userID {
			for _, reservationDate := range reservation.Period {
				if reservationDate.Before(currentTime) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func (sr *ReservationRepo) IsCancellationRateBelowThreshold(ctx context.Context, userID string, authToken string) (bool, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.IsCancellationRateBelowThreshold")
	defer span.End()

	allReservations, err := sr.GetAllReservationsByHost(ctx, userID, authToken)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting all reservations by host")
		sr.logger.Println(err)
		return false, err
	}

	cancelledReservations, err := sr.GetCancelledReservationsByHost(ctx, userID, authToken)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting cancelled reservations by host")
		sr.logger.Println(err)
		return false, err
	}

	totalReservations := len(allReservations)
	totalCancelledReservations := len(cancelledReservations)

	if totalReservations == 0 {
		sr.logger.Println("Total reservations = 0")
		return false, nil
	}

	cancellationRate := float64(totalCancelledReservations) / float64(totalReservations)

	const threshold = 0.05 // 5%

	return cancellationRate < threshold, nil
}

func (sr *ReservationRepo) HasEnoughCompletedReservations(ctx context.Context, userID string, authToken string) (bool, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.HasEnoughCompletedReservations")
	defer span.End()

	allReservations, err := sr.GetReservationsByHost(ctx, userID, authToken)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting all reservations by host")
		sr.logger.Println(err)
		return false, err
	}

	var completedReservations Reservations
	currentTime := time.Now().Truncate(24 * time.Hour)

	for _, reservation := range allReservations {
		allDatesBeforeCurrent := true

		for _, reservationDate := range reservation.Period {
			if !reservationDate.Before(currentTime) {
				allDatesBeforeCurrent = false
				break
			}
		}

		if allDatesBeforeCurrent {
			completedReservations = append(completedReservations, reservation)
		}
	}

	if len(completedReservations) >= 5 {
		return true, nil
	}

	return false, nil
}

func (sr *ReservationRepo) HasReservationsMoreThan50Days(ctx context.Context, userID string, authToken string) (bool, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.HasReservationsMoreThan50Days")
	defer span.End()

	allReservations, err := sr.GetReservationsByHost(ctx, userID, authToken)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting all reservations by host")
		sr.logger.Println(err)
		return false, err
	}

	totalDuration := 0
	currentTime := time.Now()

	for _, reservation := range allReservations {
		allDatesBeforeCurrent := true

		for _, reservationDate := range reservation.Period {
			if !reservationDate.Before(currentTime) {
				allDatesBeforeCurrent = false
				break
			}
		}

		if allDatesBeforeCurrent {
			totalDuration += len(reservation.Period)
		}

		//for _, reservationDate := range reservation.Period {
		//	if reservationDate.Before(currentTime) {
		//		totalDuration += int(currentTime.Sub(reservationDate).Hours() / 24)
		//	}
		//}
	}

	return totalDuration > 50, nil
}

func (sr *ReservationRepo) CancelReservation(ctx context.Context, reservationID string, authToken string) error {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.CancelReservation")
	defer span.End()

	reservation, err := sr.GetReservationByID(ctx, reservationID)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting reservation by ID")
		sr.logger.Println(err)
		return err
	}

	for _, date := range reservation.Period {
		if time.Now().After(date) || time.Now().Equal(date) {
			span.SetStatus(codes.Error, "Can not cancel reservation. You can only cancel it before it starts.")
			return errors.New("Can not cancel reservation. You can only cancel it before it starts.")
		}
	}

	err = sr.session.Query(
		`UPDATE reservation_by_user SET canceled = true WHERE reservation_id = ? AND by_userid = ?`,
		reservation.ID, reservation.ByUserId).Exec()
	if err != nil {
		span.SetStatus(codes.Error, "Error updating reservation status")
		sr.logger.Println(err)
		return err
	}

	err = sr.session.Query(
		`UPDATE reservation_by_accommodation SET canceled = true WHERE reservation_id = ? AND accommodation_id = ?`,
		reservation.ID, reservation.AccommodationId).Exec()
	if err != nil {
		span.SetStatus(codes.Error, "Error updating reservation status")
		sr.logger.Println(err)
		return err
	}

	accommodationEndpoint := fmt.Sprintf("http://%s:%s/%s", accommodationServiceHost, accommodationServicePort, reservation.AccommodationId)
	accommodationRequest, err := http.NewRequest("GET", accommodationEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(accommodationRequest.Header))
	if err != nil {
		span.SetStatus(codes.Error, "Error creating accommodation request")
		fmt.Println("Error creating accommodation request:", err)
		return err
	}

	accommodationRequest.Header.Set("Authorization", "Bearer "+authToken)

	accommodationResponse, err := http.DefaultClient.Do(accommodationRequest)
	if err != nil {
		span.SetStatus(codes.Error, "Error sending accommodation request")
		fmt.Println("Error sending accommodation request:", err)
		return err
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Accommodation service returned an error")
		fmt.Println("Accommodation service returned an error:", accommodationResponse.Status)
		return errors.New("Accommodation service returned an error")
	}

	type AccommodationResponse struct {
		OwnerID string `json:"ownerId"`
	}

	var response AccommodationResponse

	//err = responseToType(accommodationResponse.Body, accommodations)
	err = json.NewDecoder(accommodationResponse.Body).Decode(&response)
	if err != nil {
		span.SetStatus(codes.Error, "Error decoding accommodation response")
		fmt.Println("Error decoding accommodation response:", err)
		return err
	}

	defer accommodationResponse.Body.Close()

	usersEndpoint := fmt.Sprintf("http://%s:%s/isHighlighted/%s", usersServiceHost, usersServicePort, response.OwnerID)
	usersRequest, err := http.NewRequest("GET", usersEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(usersRequest.Header))
	if err != nil {
		span.SetStatus(codes.Error, "Error creating users request")
		fmt.Println("Error creating users request:", err)
		return err
	}

	usersRequest.Header.Set("Authorization", "Bearer "+authToken)

	usersResponse, err := http.DefaultClient.Do(usersRequest)
	if err != nil {
		span.SetStatus(codes.Error, "Error sending users request")
		fmt.Println("Error sending users request:", err)
		return err
	}

	if usersResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Users service returned an error")
		fmt.Println("Users service returned an error:", usersResponse.Status)
		return errors.New("Users service returned an error")
	}

	var response2 bool

	//err = responseToType(accommodationResponse.Body, accommodations)
	err = json.NewDecoder(usersResponse.Body).Decode(&response2)
	if err != nil {
		span.SetStatus(codes.Error, "Error decoding users response")
		fmt.Println("Error decoding users response:", err)
		return err
	}

	defer usersResponse.Body.Close()
	return nil
}

func (sr *ReservationRepo) CancelReservation2(ctx context.Context, reservationID string) error {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.CancelReservation")
	defer span.End()

	reservation, err := sr.GetReservationByID(ctx, reservationID)
	if err != nil {
		span.SetStatus(codes.Error, "Error get reservation by ID")
		sr.logger.Println(err)
		return err
	}

	for _, date := range reservation.Period {
		if time.Now().After(date) || time.Now().Equal(date) {
			span.SetStatus(codes.Error, "Can not cancel reservation. You can only cancel it before it starts.")
			return errors.New("Can not cancel reservation. You can only cancel it before it starts.")
		}
	}

	err = sr.session.Query(
		`DELETE FROM reservation_by_user WHERE reservation_id = ? AND by_userid = ?`,
		reservation.ID, reservation.ByUserId).Exec()
	if err != nil {
		span.SetStatus(codes.Error, "Error canceling reservation")
		sr.logger.Println(err)
		return err
	}
	err = sr.session.Query(
		`DELETE FROM reservation_by_accommodation WHERE reservation_id = ? AND accommodation_id = ?`,
		reservation.ID, reservation.AccommodationId).Exec()
	if err != nil {
		span.SetStatus(codes.Error, "Error canceling reservation")
		sr.logger.Println(err)
		return err
	}

	return nil
}

func (sr *ReservationRepo) DeleteReservation(ctx context.Context, reservationID string) error {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.DeleteReservation")
	defer span.End()

	reservation, err := sr.GetReservationByID(ctx, reservationID)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting reservation by ID")
		sr.logger.Println(err)
		return err
	}

	err = sr.session.Query(
		`DELETE FROM reservation_by_user WHERE reservation_id = ? AND by_userid = ?`,
		reservation.ID, reservation.ByUserId).Exec()
	if err != nil {
		span.SetStatus(codes.Error, "Error deleting reservation")
		sr.logger.Println(err)
		return err
	}
	err = sr.session.Query(
		`DELETE FROM reservation_by_accommodation WHERE reservation_id = ? AND accommodation_id = ?`,
		reservation.ID, reservation.AccommodationId).Exec()
	if err != nil {
		span.SetStatus(codes.Error, "Error deleting reservation")
		sr.logger.Println(err)
		return err
	}

	return nil
}

func (sr *ReservationRepo) GetReservationByID(ctx context.Context, reservationID string) (*Reservation, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.GetReservationByID")
	defer span.End()

	parsedUUID, err := gocql.ParseUUID(reservationID)
	if err != nil {
		span.SetStatus(codes.Error, "Error parsing UUID")
		fmt.Println("Error parsing UUID:", err, reservationID, " ", parsedUUID)
		return nil, err
	}

	scanner := sr.session.Query(
		`SELECT by_userId, reservation_id, periodd, accommodation_id, price FROM reservation_by_user WHERE reservation_id = ? ALLOW FILTERING`,
		parsedUUID).Iter().Scanner()

	var reservation Reservation
	for scanner.Next() {
		err := scanner.Scan(
			&reservation.ByUserId,
			&reservation.ID,
			&reservation.Period,
			&reservation.AccommodationId,
			&reservation.Price,
		)
		if err != nil {
			span.SetStatus(codes.Error, "Error getting reservation by ID")
			return nil, err
		}
	}

	if err := scanner.Err(); err != nil {
		span.SetStatus(codes.Error, "Error getting reservation by ID")
		sr.logger.Println(err)
		return nil, err
	}

	return &reservation, nil
}

func (sr *ReservationRepo) GetReservationByUser(ctx context.Context, id string) (Reservations, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.GetReservationByUser")
	defer span.End()

	scanner := sr.session.Query(`SELECT by_userId, reservation_id, periodd, accommodation_id, price, canceled FROM reservation_by_user WHERE by_userId = ?`, id).Iter().Scanner()

	var reservations Reservations
	for scanner.Next() {
		var r Reservation
		err := scanner.Scan(
			&r.ByUserId,
			&r.ID,
			&r.Period,
			&r.AccommodationId,
			&r.Price,
			&r.Canceled,
		)
		if err != nil {
			span.SetStatus(codes.Error, "Error getting reservation by user")
			sr.logger.Println(err)
			return nil, err
		}

		if !r.Canceled {
			reservations = append(reservations, &r)
		}
	}
	if err := scanner.Err(); err != nil {
		span.SetStatus(codes.Error, "Error getting reservation by user")
		sr.logger.Println(err)
		return nil, err
	}
	return reservations, nil
}

func (sr *ReservationRepo) GetReservationByAccommodation(ctx context.Context, id string) (Reservations, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.GetReservationByAccommodation")
	defer span.End()

	scanner := sr.session.Query(`SELECT accommodation_id, reservation_id, periodd, by_userId, price FROM reservation_by_accommodation WHERE accommodation_id = ?`, id).Iter().Scanner()

	var reservations Reservations
	for scanner.Next() {
		var r Reservation
		err := scanner.Scan(
			&r.AccommodationId,
			&r.ID,
			&r.Period,
			&r.ByUserId,
			&r.Price,
		)
		if err != nil {
			span.SetStatus(codes.Error, "Error getting reservation by accommodation")
			sr.logger.Println(err)
			return nil, err
		}

		reservations = append(reservations, &r)
	}
	if err := scanner.Err(); err != nil {
		span.SetStatus(codes.Error, "Error getting reservation by accommodation")
		sr.logger.Println(err)
		return nil, err
	}
	return reservations, nil
}

// NoSQL: Performance issue, we never want to fetch all the data
// (In order to get all student ids we need to contact every partition which are usually located on different servers!)
// Here we are doing it for demonstration purposes (so we can see all student/predmet ids)
func (sr *ReservationRepo) GetDistinctIds(idColumnName string, tableName string) ([]string, error) {
	scanner := sr.session.Query(
		fmt.Sprintf(`SELECT DISTINCT %s FROM %s`, idColumnName, tableName)).
		Iter().Scanner()
	var ids []string
	for scanner.Next() {
		var id string
		err := scanner.Scan(&id)
		if err != nil {
			sr.logger.Println(err)
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := scanner.Err(); err != nil {
		sr.logger.Println(err)
		return nil, err
	}
	return ids, nil
}

func (sr *ReservationRepo) getAppointmentsByAccommodation(ctx context.Context, id string, token string) (Appointments, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.GetReservationByAccommodation")
	defer span.End()

	reservationServiceEndpoint := fmt.Sprintf("https://%s:%s/appointmentsByAccommodation/%s", reservationServiceHost, reservationServicePort, id)
	response, _ := sr.HTTPSRequestWithouthBody(ctx, token, reservationServiceEndpoint, "GET")
	if response.StatusCode != 200 {
		if response.StatusCode == 404 {
			span.SetStatus(codes.Error, "Appointments not found")
			return nil, errors.New("Appointments not found")
		}
	}

	var appointments Appointments
	err := responseToType(response.Body, &appointments)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting appointments by accommodation")
		return nil, err
	}

	return appointments, nil
}

func responseToType(response io.ReadCloser, any any) error {
	responseBodyBytes, err := io.ReadAll(response)
	if err != nil {
		log.Printf("err in readAll %s", err.Error())
		return err
	}

	err = json.Unmarshal(responseBodyBytes, &any)
	if err != nil {
		log.Printf("err in Unmarshal %s", err.Error())
		return err
	}

	return nil
}

func (sr *ReservationRepo) HTTPSRequestWithouthBody(ctx context.Context, token string, url string, method string) (*http.Response, error) {
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
