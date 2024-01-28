package data

import (
	"context"
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
	"log"
	"net/http"
	"os"
	"time"
)

type AccommodationRepo struct {
	cli    *mongo.Client
	logger *log.Logger
	client *http.Client
	tracer trace.Tracer
}

var (
	reservationServiceHost = os.Getenv("RESERVATIONS_SERVICE_HOST")
	reservationServicePort = os.Getenv("RESERVATIONS_SERVICE_PORT")
	usersServiceHost       = os.Getenv("USER_SERVICE_HOST")
	usersServicePort       = os.Getenv("USER_SERVICE_PORT")
)

func New(ctx context.Context, logger *log.Logger, tracer trace.Tracer) (*AccommodationRepo, error) {
	dburi := fmt.Sprintf("mongodb://%s:%s/", os.Getenv("ACCOMMODATIONS_DB_HOST"), os.Getenv("ACCOMMODATIONS_DB_PORT"))

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
	return &AccommodationRepo{
		cli:    client,
		logger: logger,
		client: httpClient,
		tracer: tracer,
	}, nil
}

// Disconnect from database
func (pr *AccommodationRepo) DisconnectMongo(ctx context.Context) error {
	err := pr.cli.Disconnect(ctx)
	if err != nil {
		return err
	}
	return nil
}

// Check database connection
func (rr *AccommodationRepo) Ping() {
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

func (rr *AccommodationRepo) InsertAccommodation(ctx context.Context, accommodation *Accommodation) (string, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.InsertAccommodation")
	defer span.End()

	accommodationCollection := rr.getCollection(ctx)

	result, err := accommodationCollection.InsertOne(ctx, accommodation)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		rr.logger.Println(err)
		return "", err
	}

	insertedID, ok := result.InsertedID.(primitive.ObjectID)
	if !ok {
		span.AddEvent("Failed to convert InsertedID to ObjectID")
		rr.logger.Println("Failed to convert InsertedID to ObjectID")
		return "", errors.New("Failed to convert InsertedID")
	}

	return insertedID.Hex(), nil
}

func (rr *AccommodationRepo) InsertRateForAccommodation(ctx context.Context, rate *Rate) (string, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.InsertRateForAccommodation")
	defer span.End()

	rateCollection := rr.getRateCollection(ctx)

	_, err := rateCollection.InsertOne(ctx, rate)
	if err != nil {
		span.SetStatus(codes.Error, "Error insert rate for accommodation")
		rr.logger.Println(err)
		return "", err
	}

	return "", nil
}

func (rr *AccommodationRepo) InsertRateForHost(ctx context.Context, rate *Rate, authToken string) (string, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.InsertRateForHost")
	defer span.End()

	rateCollection := rr.getRateCollection(ctx)

	_, err := rateCollection.InsertOne(ctx, rate)
	if err != nil {
		span.SetStatus(codes.Error, "Error insert rate for host")
		rr.logger.Println(err)
		return "", err
	}

	usersEndpoint := fmt.Sprintf("http://%s:%s/isHighlighted/%s", usersServiceHost, usersServicePort, rate.ForHostId)
	usersRequest, err := http.NewRequest("GET", usersEndpoint, nil)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(usersRequest.Header))
	if err != nil {
		span.SetStatus(codes.Error, "Error creating users request")
		fmt.Println("Error creating users request:", err)
		return "Error creating users request:", err
	}

	usersRequest.Header.Set("Authorization", "Bearer "+authToken)

	usersResponse, err := http.DefaultClient.Do(usersRequest)
	if err != nil {
		span.SetStatus(codes.Error, "Error sending users request")
		fmt.Println("Error sending users request:", err)
		return "Error sending users request:", err
	}

	if usersResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Users service returned an error")
		fmt.Println("Users service returned an error:", usersResponse.Status)
		return "Users service returned an error:", errors.New("Users service returned an error")
	}

	var response2 bool

	//err = responseToType(accommodationResponse.Body, accommodations)
	err = json.NewDecoder(usersResponse.Body).Decode(&response2)
	if err != nil {
		span.SetStatus(codes.Error, "Error decoding users response")
		fmt.Println("Error decoding users response:", err)
		return "Error decoding users response:", err
	}

	defer usersResponse.Body.Close()

	return "", nil
}

func (rr *AccommodationRepo) DeleteRateForHost(ctx context.Context, rateID string, authToken string) error {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.DeleteRateForHost")
	defer span.End()

	objID, err := primitive.ObjectIDFromHex(rateID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		rr.logger.Println(err)
		return err
	}

	rateCollection := rr.getRateCollection(ctx)

	filter := bson.M{"_id": objID}

	var rate Rate
	err = rateCollection.FindOne(ctx, filter).Decode(&rate)
	if err != nil {
		span.SetStatus(codes.Error, "Error finding rate")
		rr.logger.Println(err)
		return err
	}

	_, err2 := rateCollection.DeleteOne(ctx, filter)
	if err2 != nil {
		span.SetStatus(codes.Error, "Error delete rate")
		rr.logger.Println(err2)
		return err2
	}

	usersEndpoint := fmt.Sprintf("http://%s:%s/isHighlighted/%s", usersServiceHost, usersServicePort, rate.ForHostId)
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
func (rr *AccommodationRepo) UpdateRateForHost(ctx context.Context, rateID string, rate *Rate, authToken string) error {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.UpdateRateForHost")
	defer span.End()

	rateId, err := primitive.ObjectIDFromHex(rateID)
	if err != nil {
		span.SetStatus(codes.Error, "Error converting ID to ObjectID")
		fmt.Println("Error converting ID to ObjectID:", err)
		return err
	}

	filter := bson.M{"_id": rateId}

	var foundRate Rate
	err = rr.getRateCollection(ctx).FindOne(ctx, filter).Decode(&foundRate)
	if err != nil {
		span.SetStatus(codes.Error, "Error finding rate by ID")
		fmt.Println("Error finding rate by ID:", err)
		return err
	}

	if rate.Rate <= 0 || rate.Rate > 5 {
		span.SetStatus(codes.Error, "Invalid rate value")
		return fmt.Errorf("Invalid rate value: %v. Rate must be between 0 and 5", rate.Rate)
	}

	update := bson.M{"$set": bson.M{"rate": rate.Rate, "updatedAt": rate.UpdatedAt}}

	result, err := rr.getRateCollection(ctx).UpdateOne(ctx, filter, update)

	if err != nil {
		span.SetStatus(codes.Error, "Error updating rate")
		rr.logger.Println("Error updating rate:", err)
		return err
	}

	rr.logger.Printf("Documents matched: %v\n", result.MatchedCount)
	rr.logger.Printf("Documents updated: %v\n", result.ModifiedCount)

	usersEndpoint := fmt.Sprintf("http://%s:%s/isHighlighted/%s", usersServiceHost, usersServicePort, foundRate.ForHostId)
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

func (rr *AccommodationRepo) getCollection(ctx context.Context) *mongo.Collection {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.getCollection")
	defer span.End()

	accommodationDatabase := rr.cli.Database("MongoDatabase")
	accommodationCollection := accommodationDatabase.Collection("accommodations")
	return accommodationCollection
}

func (rr *AccommodationRepo) getRateCollection(ctx context.Context) *mongo.Collection {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.getRateCollection")
	defer span.End()

	rateDatabase := rr.cli.Database("MongoDatabase")
	rateCollection := rateDatabase.Collection("rates")
	return rateCollection
}

func (rr *AccommodationRepo) GetAll(ctx context.Context) ([]*Accommodation, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.GetAll")
	defer span.End()

	filter := bson.D{{}}
	return rr.filter(ctx, filter)
}

func (rr *AccommodationRepo) GetAllRate(ctx context.Context) ([]*Rate, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.GetAllRate")
	defer span.End()

	filter := bson.D{{}}
	return rr.filterRate(ctx, filter)
}

func (rr *AccommodationRepo) GetRateById(ctx context.Context, id primitive.ObjectID) (*Rate, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.GetRateById")
	defer span.End()

	filter := bson.D{{"_id", id}}
	return rr.getRateByFilter(ctx, filter)
}

func (rr *AccommodationRepo) GetByID(ctx context.Context, id primitive.ObjectID) (*Accommodation, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.GetByID")
	defer span.End()

	filter := bson.D{{"_id", id}}
	return rr.getByFilter(ctx, filter)
}

func (rr *AccommodationRepo) GetRatesByAccommodation(ctx context.Context, id string) ([]*Rate, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.GetRatesByAccommodation")
	defer span.End()

	filter := bson.D{{"forAccommodationId", id}}
	return rr.filterRate(ctx, filter)
}

func (rr *AccommodationRepo) GetRatesByHost(ctx context.Context, id string) ([]*Rate, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.GetRatesByHost")
	defer span.End()

	filter := bson.D{{"forHostId", id}}
	return rr.filterRate(ctx, filter)
}

func (rr *AccommodationRepo) getByFilter(ctx context.Context, filter interface{}) (*Accommodation, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.getByFilter")
	defer span.End()

	accommodationCollection := rr.getCollection(ctx)

	var accommodation Accommodation
	err := accommodationCollection.FindOne(ctx, filter).Decode(&accommodation)
	if err != nil {
		span.SetStatus(codes.Error, "Error finding accommodation by filter")
		return nil, err
	}

	return &accommodation, nil
}

func (rr *AccommodationRepo) getRateByFilter(ctx context.Context, filter interface{}) (*Rate, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.getRateByFilter")
	defer span.End()

	rateCollection := rr.getRateCollection(ctx)

	var rate Rate
	err := rateCollection.FindOne(ctx, filter).Decode(&rate)
	if err != nil {
		return nil, err
	}

	return &rate, nil
}

func (rr *AccommodationRepo) Search(ctx context.Context, filter interface{}) ([]*Accommodation, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.Search")
	defer span.End()

	return rr.filter(ctx, filter)
}

func (rr *AccommodationRepo) GetAccommodationsByOwner(ctx context.Context, ownerID string) ([]primitive.ObjectID, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.GetAccommodationsByOwner")
	defer span.End()

	filter := bson.D{{"ownerId", ownerID}}
	return rr.filterIDs(ctx, filter)
}

func (rr *AccommodationRepo) DeleteAccommodationsByOwner(ctx context.Context, ownerID string) error {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.GetAccommodationsByOwner")
	defer span.End()

	owner, err := primitive.ObjectIDFromHex(ownerID)
	if err != nil {
		span.SetStatus(codes.Error, "Error converting ID to ObjectID")
		fmt.Println("Error converting ID to ObjectID:", owner, err)
		return err
	}

	accommodationsCollection := rr.getCollection(ctx)

	filter := bson.M{"ownerId": ownerID}

	_, err2 := accommodationsCollection.DeleteMany(ctx, filter)
	if err2 != nil {
		span.SetStatus(codes.Error, "Error deleting accommodations by owner")
		rr.logger.Println(err2)
		return err2
	}

	return nil
}

func (rr *AccommodationRepo) HasUserRatedHost(ctx context.Context, userID string, hostID string) (bool, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.HasUserRatedHost")
	defer span.End()

	rateCollection := rr.getRateCollection(ctx)

	filter := bson.D{
		{"byGuestId", userID},
		{"forHostId", hostID},
	}

	count, err := rateCollection.CountDocuments(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, "Error counting rates")
		return false, err
	}

	return count > 0, nil
}

func (rr *AccommodationRepo) HasUserRatedAccommodation(ctx context.Context, userID string, accommodationId string) (bool, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.HasUserRatedAccommodation")
	defer span.End()

	rateCollection := rr.getRateCollection(ctx)

	filter := bson.D{
		{"byGuestId", userID},
		{"forAccommodationId", accommodationId},
	}

	count, err := rateCollection.CountDocuments(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, "Error counting rates")
		return false, err
	}

	return count > 0, nil
}

func (rr *AccommodationRepo) AverageRate(ctx context.Context, hostID string) (float64, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.averageRate")
	defer span.End()

	rateCollection := rr.getRateCollection(ctx)

	filter := bson.D{
		{"forHostId", hostID},
	}

	opts := options.Find().SetProjection(bson.D{{"rate", 1}}).SetSort(bson.D{{"createdAt", -1}})

	cursor, err := rateCollection.Find(ctx, filter, opts)
	if err != nil {
		return 0, err
	}
	defer cursor.Close(ctx)

	var sum float64
	var count int
	for cursor.Next(ctx) {
		var rate Rate
		if err := cursor.Decode(&rate); err != nil {
			return 0, err
		}
		sum += float64(rate.Rate)
		count++
	}

	if count == 0 {
		return 0, nil
	}

	prosecnaOcena := sum / float64(count)
	return prosecnaOcena, nil
}

func (rr *AccommodationRepo) filterIDs(ctx context.Context, filter interface{}) ([]primitive.ObjectID, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.filterIDs")
	defer span.End()

	accommodationCollection := rr.getCollection(ctx)
	cursor, err := accommodationCollection.Find(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, "Error finding accommodation by filter")
		return nil, err
	}
	defer cursor.Close(ctx)

	var accommodationIDs []primitive.ObjectID
	for cursor.Next(ctx) {
		var accommodation Accommodation
		if err := cursor.Decode(&accommodation); err != nil {
			span.SetStatus(codes.Error, "Error decoding accommodation")
			return nil, err
		}
		accommodationIDs = append(accommodationIDs, accommodation.ID)
	}

	if err := cursor.Err(); err != nil {
		span.SetStatus(codes.Error, "Error getting accommodations")
		return nil, err
	}

	return accommodationIDs, nil
}

func (rr *AccommodationRepo) filter(ctx context.Context, filter interface{}) ([]*Accommodation, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.filter")
	defer span.End()

	accommodationCollection := rr.getCollection(ctx)
	cursor, err := accommodationCollection.Find(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, "Error finding accommodation by filter")
		return nil, err
	}
	defer cursor.Close(ctx)

	return decode(cursor)
}

func (rr *AccommodationRepo) filterRate(ctx context.Context, filter interface{}) ([]*Rate, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.filterRate")
	defer span.End()

	rateCollection := rr.getRateCollection(ctx)
	cursor, err := rateCollection.Find(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, "Error finding rate by filter")
		return nil, err
	}
	defer cursor.Close(ctx)

	return decodeRate(cursor)
}

func decode(cursor *mongo.Cursor) (users []*Accommodation, err error) {
	for cursor.Next(context.TODO()) {
		var user Accommodation
		err = cursor.Decode(&user)
		if err != nil {
			return
		}
		users = append(users, &user)
	}
	err = cursor.Err()
	return
}

func decodeRate(cursor *mongo.Cursor) (rates []*Rate, err error) {
	for cursor.Next(context.TODO()) {
		var rate Rate
		err = cursor.Decode(&rate)
		if err != nil {
			return
		}
		rates = append(rates, &rate)
	}
	err = cursor.Err()
	return
}
