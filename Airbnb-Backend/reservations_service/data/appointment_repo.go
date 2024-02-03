package data

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type AppointmentRepo struct {
	cli    *mongo.Client
	logger *log.Logger
	client *http.Client
	tracer trace.Tracer
}

func NewAppointmentRepo(ctx context.Context, logger *log.Logger, tracer trace.Tracer) (*AppointmentRepo, error) {
	dburi := fmt.Sprintf("mongodb://%s:%s/", os.Getenv("APPOINTMENTS_DB_HOST"), os.Getenv("APPOINTMENTS_DB_PORT"))

	client, err := mongo.NewClient(options.Client().ApplyURI(dburi))
	if err != nil {
		return nil, err
	}

	err = client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			MaxConnsPerHost:     10,
		},
	}

	// Return repository with logger and DB client
	return &AppointmentRepo{
		logger: logger,
		cli:    client,
		client: httpClient,
		tracer: tracer,
	}, nil
}

// Disconnect from database
func (pr *AppointmentRepo) DisconnectMongo(ctx context.Context) error {
	err := pr.cli.Disconnect(ctx)
	if err != nil {
		return err
	}
	return nil
}

// Check database connection
func (rr *AppointmentRepo) Ping() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check connection -> if no error, connection is established
	err := rr.cli.Ping(ctx, readpref.Primary())
	if err != nil {
		rr.logger.Println(err)
	}

	// Print available databases
	databases, err := rr.cli.ListDatabaseNames(ctx, bson.M{})
	if err != nil {
		rr.logger.Println(err)
	}
	fmt.Println(databases)
}

// mongo
func (rr *AppointmentRepo) InsertAppointment(ctx context.Context, appointment *Appointment) error {
	ctx, span := rr.tracer.Start(ctx, "AppointmentRepo.InsertAppointment")
	defer span.End()
	appointmentsCollection := rr.getCollection()

	if appointment.PricePerGuest != 0 && appointment.PricePerAccommodation != 0 {
		span.SetStatus(codes.Error, "Error adding accommodation price and guest price at the same time.")
		rr.logger.Printf("Error adding accommodation price and guest price at the same time.")
		return errors.New("Error adding accommodation price and guest price at the same time.")
	}

	existingAppointments, err := rr.GetAppointmentsByAccommodation(ctx, appointment.AccommodationId)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting appointments by accommodation")
		return err
	}

	for _, existingAppointment := range existingAppointments {
		for _, existAppointment := range existingAppointment.Available {
			for _, newAppointment := range appointment.Available {
				if newAppointment.Equal(existAppointment) {
					return errors.New("Error adding appointment. Date already exists. ")
				}
			}
		}
	}

	for _, newAppointment := range appointment.Available {
		if time.Now().After(newAppointment) {
			span.SetStatus(codes.Error, "Error adding appointment. Cannot add appointment in the past.")
			return errors.New("Error adding appointment. Cannot add appointment in the past.")
		}
	}

	result, err := appointmentsCollection.InsertOne(ctx, &appointment)
	if err != nil {
		span.SetStatus(codes.Error, "Error inserting appointment")
		rr.logger.Println(err)
		return err
	}
	rr.logger.Printf("Documents ID: %v\n", result.InsertedID)
	return nil
}

func extractTokenFromHeader(request *http.Request) (string, error) {
	authHeader := request.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("No Authorization header found")
	}

	// Check if the header starts with "Bearer "
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("Invalid Authorization header format")
	}

	// Extract the token
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	return tokenString, nil
}

func (rr *AppointmentRepo) UpdateAppointment(ctx context.Context, id string, appointment *Appointment, token string) error {
	ctx, span := rr.tracer.Start(ctx, "AppointmentRepository.UpdateAppointment")
	defer span.End()

	originalAppointment, err := rr.GetAppointmentByID(ctx, id)
	if err != nil {
		span.SetStatus(codes.Error, "Error retrieving original appointment")
		rr.logger.Println("Error retrieving original appointment:", err)
		return err
	}

	data := map[string]interface{}{
		"accommodationId": originalAppointment.AccommodationId,
		"available":       originalAppointment.Available,
	}

	appointmentsCollection := rr.getCollection()

	reservationEndpoint := fmt.Sprintf("https://%s:%s/check", reservationServiceHost, reservationServicePort)
	reservationResponse, err := rr.HTTPSRequestWithBody(ctx, token, reservationEndpoint, "POST", data)
	if err != nil {
		span.SetStatus(codes.Error, "Error sending reservation request")
		rr.logger.Println("Error sending reservation request:", err)
		return err
	}
	defer reservationResponse.Body.Close()

	if reservationResponse.StatusCode == http.StatusOK {
		existingAppointments, err := rr.GetAppointmentsByAccommodation(ctx, originalAppointment.AccommodationId)
		if err != nil {
			span.SetStatus(codes.Error, "Error getting appointments by accommodation")
			return err
		}

		for _, existingAppointment := range existingAppointments {
			if existingAppointment.ID == originalAppointment.ID {
				continue
			}
			for _, existAppointment := range existingAppointment.Available {
				for _, newAppointment := range appointment.Available {

					if newAppointment.Equal(existAppointment) {
						span.SetStatus(codes.Error, "Error editing appointment. Date already exists,")
						return errors.New("Error editing appointment. Date already exists. ")
					}

				}
			}

		}

		for _, newAppointment := range appointment.Available {
			span.SetStatus(codes.Error, "Error editing appointment. Cannot add appointment in the past.")
			if time.Now().After(newAppointment) {
				return errors.New("Error editing appointment. Cannot add appointment in the past.")
			}
		}

		if appointment.PricePerGuest != 0 && appointment.PricePerAccommodation != 0 {
			span.SetStatus(codes.Error, "Error adding accommodation price and guest price at the same time.")
			rr.logger.Printf("Error adding accommodation price and guest price at the same time.")
			return errors.New("Error adding accommodation price and guest price at the same time.")
		}

		rr.logger.Println("No reservation found for the appointment. Update allowed.")
		objectID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			span.SetStatus(codes.Error, "Error converting ID to ObjectID")
			rr.logger.Println("Error converting ID to ObjectID:", err)
			return err
		}

		// Ažurirajte podatke u appointmentsCollection
		filter := bson.M{"_id": objectID}
		update := bson.M{}

		if appointment.Available != nil {
			update["available"] = appointment.Available
		}

		if appointment.PricePerGuest != 0 {
			update["pricePerGuest"] = appointment.PricePerGuest
		}

		if appointment.PricePerAccommodation != 0 {
			update["pricePerAccommodation"] = appointment.PricePerAccommodation
		}

		updateQuery := bson.M{"$set": update}

		result, err := appointmentsCollection.UpdateOne(ctx, filter, updateQuery)

		rr.logger.Printf("Documents matched: %v\n", result.MatchedCount)
		rr.logger.Printf("Documents updated: %v\n", result.ModifiedCount)

		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			rr.logger.Println(err)
			return err
		}
	} else if reservationResponse.StatusCode == http.StatusBadRequest {
		rr.logger.Println("Reservation exists for the appointment. Update not allowed.")

		return errors.New("Reservation exists for the appointment.")
	} else {
		buf := new(strings.Builder)
		_, _ = io.Copy(buf, reservationResponse.Body)
		return fmt.Errorf("Reservation service error: %v", buf.String())
	}

	return nil
}

func (rr *AppointmentRepo) DeleteAppointmentsByAccommodationID(ctx context.Context, accommodationID string) error {
	ctx, span := rr.tracer.Start(ctx, "AppointmentRepository.DeleteAppointmentsByAccommodationID")
	defer span.End()

	fmt.Println("lolaa", accommodationID)
	appointmentsCollection := rr.getCollection()

	filter := bson.M{"accommodationId": accommodationID}

	result, err := appointmentsCollection.DeleteMany(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, "Error deleting appointments")
		rr.logger.Println(err)
		return err
	}

	rr.logger.Printf("Deleted appointments count: ", result.DeletedCount)

	return nil
}

func (rr *AppointmentRepo) GetAppointmentByID(ctx context.Context, id string) (*Appointment, error) {
	ctx, span := rr.tracer.Start(ctx, "AppointmentRepository.GetAppointmentByID")
	defer span.End()

	appointmentsCollection := rr.getCollection()

	var appointment Appointment
	objID, _ := primitive.ObjectIDFromHex(id)
	err := appointmentsCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&appointment)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting appointment by ID")
		rr.logger.Println(err)
		return nil, err
	}
	return &appointment, nil
}

func (rr *AppointmentRepo) GetAllAppointment(ctx context.Context) (*Appointments, error) {
	ctx, span := rr.tracer.Start(ctx, "AppointmentRepository.GetAllAppointment")
	defer span.End()

	appointmentsCollection := rr.getCollection()

	var appointments Appointments
	appointmentCursor, err := appointmentsCollection.Find(ctx, bson.M{})
	if err != nil {
		span.SetStatus(codes.Error, "Error getting all appointments")
		rr.logger.Println(err)
		return nil, err
	}
	if err = appointmentCursor.All(ctx, &appointments); err != nil {
		span.SetStatus(codes.Error, "Error getting all appointments")
		rr.logger.Println(err)
		return nil, err
	}
	return &appointments, nil
}

func (rr *AppointmentRepo) GetAppointmentsByAccommodation(ctx context.Context, id string) (Appointments, error) {
	ctx, span := rr.tracer.Start(ctx, "AppointmentRepository.GetAppointmentsByAccommodation")
	defer func() {
		// Check if span is not nil before calling End()
		if span != nil {
			span.End()
		}
	}()

	appointmentsCollection := rr.getCollection()

	idValid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		span.SetStatus(codes.Error, "Error converting ID to ObjectID")
		fmt.Println("Error converting ID to ObjectID:", idValid, err)
		return nil, err
	}

	filter := bson.M{"accommodationId": id}

	// Find appointments matching the filter
	cursor, err := appointmentsCollection.Find(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, "Error finding appointments by filter")
		rr.logger.Println(err)
		return nil, err
	}
	defer cursor.Close(ctx)

	// Iterate over the cursor and decode each appointment
	var appointments Appointments
	for cursor.Next(ctx) {
		var appointment Appointment
		if err := cursor.Decode(&appointment); err != nil {
			span.SetStatus(codes.Error, "Error decoding appointment")
			rr.logger.Println(err)
			return nil, err
		}
		appointments = append(appointments, &appointment)
	}

	// Check for errors during cursor iteration
	if err := cursor.Err(); err != nil {
		span.SetStatus(codes.Error, "Error getting appointments")
		rr.logger.Println(err)
		return nil, err
	}

	return appointments, nil
}
func (rr *AppointmentRepo) GetAppointmentsByDate(ctx context.Context, startDate, endDate time.Time) (Appointments, error) {
	ctx, span := rr.tracer.Start(ctx, "AppointmentRepository.GetAppointmentsByDate")
	defer span.End()

	appointmentsCollection := rr.getCollection()

	filter := bson.M{
		"$and": []bson.M{
			{"available": bson.M{"$lte": startDate}},
			{"available": bson.M{"$gte": endDate}},
		},
	}
	fmt.Printf("MongoDB Query: %+v\n", filter)

	cursor, err := appointmentsCollection.Find(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting appointments")
		rr.logger.Printf("Error querying MongoDB: %v\n", err)
		return nil, err
	}
	defer cursor.Close(ctx)

	var appointments Appointments
	for cursor.Next(ctx) {
		var appointment Appointment
		if err := cursor.Decode(&appointment); err != nil {
			span.SetStatus(codes.Error, "Error decoding")
			rr.logger.Printf("Error decoding result: %v\n", err)
			return nil, err
		}

		appointments = append(appointments, &appointment)
	}

	if err := cursor.Err(); err != nil {
		span.SetStatus(codes.Error, "Error getting appointments by date")
		rr.logger.Printf("Cursor error: %v\n", err)
		return nil, err
	}

	return appointments, nil
}

func (rr *AppointmentRepo) getCollection() *mongo.Collection {
	appointmentDatabase := rr.cli.Database("MongoDatabase")
	appointmentsCollection := appointmentDatabase.Collection("appointments")
	return appointmentsCollection
}

func (rr *AppointmentRepo) HTTPSRequestWithBody(ctx context.Context, token string, url string, method string, requestBody interface{}) (*http.Response, error) {
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
