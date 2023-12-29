package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"io"
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
					(by_userId text,reservation_id UUID, periodd LIST<TIMESTAMP>, accommodation_id text, price int,
					PRIMARY KEY ((by_userId), reservation_id)) 
					WITH CLUSTERING ORDER BY (reservation_id ASC)`, "reservation_by_user")).Exec()
	if err != nil {
		sr.logger.Println(err)
	}

	err = sr.session.Query(
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s 
					(by_userId text,reservation_id UUID, periodd LIST<TIMESTAMP>, accommodation_id text, price int,
					PRIMARY KEY ((accommodation_id), reservation_id)) 
					WITH CLUSTERING ORDER BY (reservation_id ASC)`, "reservation_by_accommodation")).Exec()
	if err != nil {
		sr.logger.Println(err)
	}

}

// cassandra
func (sr *ReservationRepo) InsertReservation(ctx context.Context, reservation *Reservation) (*Reservation, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.InsertReservation")
	defer span.End()

	exists, err := sr.ReservationExistsForAppointment(ctx, reservation.AccommodationId, reservation.Period)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if exists {
		span.SetStatus(codes.Error, "Reservation already exists for the specified dates and accommodation.")
		return nil, errors.New("Reservation already exists for the specified dates and accommodation.")
	}

	reservationId, _ := gocql.RandomUUID()

	appointments, err := sr.getAppointmentsByAccommodation(ctx, reservation.AccommodationId)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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

	err = sr.session.Query(
		`INSERT INTO reservation_by_user (by_userId, reservation_id, periodd, accommodation_id, price) 
        VALUES (?, ?, ?, ?, ?)`,
		reservation.ByUserId, reservationId, reservation.Period, reservation.AccommodationId, reservation.Price).Exec()
	if err != nil {
		sr.logger.Println(err)
		return nil, err
	}

	err = sr.session.Query(
		`INSERT INTO reservation_by_accommodation (by_userId, reservation_id, periodd, accommodation_id, price) 
        VALUES (?, ?, ?, ?, ?)`,
		reservation.ByUserId, reservationId, reservation.Period, reservation.AccommodationId, reservation.Price).Exec()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		sr.logger.Println(err)
		return nil, err
	}

	createdReservation := &Reservation{
		ID:              reservationId,
		ByUserId:        reservation.ByUserId,
		Period:          reservation.Period,
		AccommodationId: reservation.AccommodationId,
		Price:           reservation.Price,
	}

	return createdReservation, nil
}

func (sr *ReservationRepo) ReservationExistsForAppointment(ctx context.Context, accommodationID string, available []time.Time) (bool, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.ReservationExistsForAppointment")
	defer span.End()

	allReservations, err := sr.GetReservationByAccommodation(ctx, accommodationID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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

	accommodationEndpoint := fmt.Sprintf("http://%s:%s/owner/%s", accommodationServiceHost, accommodationServicePort, userID)
	accommodationRequest, err := http.NewRequest("GET", accommodationEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(accommodationRequest.Header))
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		sr.logger.Println("Error creating accommodation request:", err)
		return false, err
	}

	accommodationRequest.Header.Set("Authorization", "Bearer "+authToken)

	accommodationResponse, err := http.DefaultClient.Do(accommodationRequest)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		sr.logger.Println("Error sending accommodation request:", err)
		return false, err
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Accommodation service returned an error")
		sr.logger.Println("Accommodation service returned an error:", accommodationResponse.Status)
		return false, errors.New("Accommodation service returned an error")
	}

	var accommodations []primitive.ObjectID

	//err = responseToType(accommodationResponse.Body, accommodations)
	err = json.NewDecoder(accommodationResponse.Body).Decode(&accommodations)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		sr.logger.Println("Error decoding accommodation response:", err)
		return false, err
	}

	defer accommodationResponse.Body.Close()
	for _, accommodationID := range accommodations {
		hasReservations, err := sr.HasReservationsForAccommodation(ctx, accommodationID)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			sr.logger.Println(err)
			return false, err
		}

		if hasReservations {
			return true, nil
		}
	}

	return false, nil
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
			span.SetStatus(codes.Error, err.Error())
			sr.logger.Println(err)
			return false, err
		}
	} else {
		return false, nil
	}

	if err := scanner.Err(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		sr.logger.Println(err)
		return false, err
	}
	return count > 0, nil
}

func (sr *ReservationRepo) CheckUserPastReservations(ctx context.Context, userID string, hostID string, token string) (bool, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.CheckUserPastReservations")
	defer span.End()

	accommodationEndpoint := fmt.Sprintf("http://%s:%s/owner/%s", accommodationServiceHost, accommodationServicePort, hostID)
	accommodationRequest, err := http.NewRequest("GET", accommodationEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(accommodationRequest.Header))
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		sr.logger.Println("Error creating accommodation request:", err)
		return false, err
	}

	accommodationRequest.Header.Set("Authorization", "Bearer "+token)

	accommodationResponse, err := http.DefaultClient.Do(accommodationRequest)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
		span.SetStatus(codes.Error, err.Error())
		sr.logger.Println("Error decoding accommodation response:", err)
		return false, err
	}

	defer accommodationResponse.Body.Close()

	reservations, err := sr.GetReservationByUser(ctx, userID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
		span.SetStatus(codes.Error, err.Error())
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

func (sr *ReservationRepo) CancelReservation(ctx context.Context, reservationID string) error {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.CancelReservation")
	defer span.End()

	reservation, err := sr.GetReservationByID(ctx, reservationID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
		span.SetStatus(codes.Error, err.Error())
		sr.logger.Println(err)
		return err
	}
	err = sr.session.Query(
		`DELETE FROM reservation_by_accommodation WHERE reservation_id = ? AND accommodation_id = ?`,
		reservation.ID, reservation.AccommodationId).Exec()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
		span.SetStatus(codes.Error, err.Error())
		sr.logger.Println(err)
		return err
	}

	err = sr.session.Query(
		`DELETE FROM reservation_by_user WHERE reservation_id = ? AND by_userid = ?`,
		reservation.ID, reservation.ByUserId).Exec()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		sr.logger.Println(err)
		return err
	}
	err = sr.session.Query(
		`DELETE FROM reservation_by_accommodation WHERE reservation_id = ? AND accommodation_id = ?`,
		reservation.ID, reservation.AccommodationId).Exec()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
		span.SetStatus(codes.Error, err.Error())
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
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
	}

	if err := scanner.Err(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		sr.logger.Println(err)
		return nil, err
	}

	return &reservation, nil
}

func (sr *ReservationRepo) GetReservationByUser(ctx context.Context, id string) (Reservations, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.GetReservationByUser")
	defer span.End()

	scanner := sr.session.Query(`SELECT by_userId, reservation_id, periodd, accommodation_id, price FROM reservation_by_user WHERE by_userId = ?`, id).Iter().Scanner()

	var reservations Reservations
	for scanner.Next() {
		var r Reservation
		err := scanner.Scan(
			&r.ByUserId,
			&r.ID,
			&r.Period,
			&r.AccommodationId,
			&r.Price,
		)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			sr.logger.Println(err)
			return nil, err
		}

		reservations = append(reservations, &r)
	}
	if err := scanner.Err(); err != nil {
		span.SetStatus(codes.Error, err.Error())
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
			span.SetStatus(codes.Error, err.Error())
			sr.logger.Println(err)
			return nil, err
		}

		reservations = append(reservations, &r)
	}
	if err := scanner.Err(); err != nil {
		span.SetStatus(codes.Error, err.Error())
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

func (sr *ReservationRepo) getAppointmentsByAccommodation(ctx context.Context, id string) (Appointments, error) {
	ctx, span := sr.tracer.Start(ctx, "ReservationRepo.GetReservationByAccommodation")
	defer span.End()

	reservationServiceEndpoint := fmt.Sprintf("http://%s:%s/appointmentsByAccommodation/%s", reservationServiceHost, reservationServicePort, id)
	reservationServiceRequest, _ := http.NewRequest("GET", reservationServiceEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(reservationServiceRequest.Header))
	response, _ := http.DefaultClient.Do(reservationServiceRequest)
	if response.StatusCode != 200 {
		if response.StatusCode == 404 {
			span.SetStatus(codes.Error, "Appointments not found")
			return nil, errors.New("Appointments not found")
		}
	}

	var appointments Appointments
	err := responseToType(response.Body, &appointments)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
