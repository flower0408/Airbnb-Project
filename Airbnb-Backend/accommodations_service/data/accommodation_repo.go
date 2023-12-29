package data

import (
	"context"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.opentelemetry.io/otel/codes"
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
		span.SetStatus(codes.Error, err.Error())
		rr.logger.Println(err)
		return "", err
	}

	return "", nil
}

func (rr *AccommodationRepo) InsertRateForHost(ctx context.Context, rate *Rate) (string, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.InsertRateForHost")
	defer span.End()

	rateCollection := rr.getRateCollection(ctx)

	_, err := rateCollection.InsertOne(ctx, rate)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		rr.logger.Println(err)
		return "", err
	}

	return "", nil
}

func (rr *AccommodationRepo) DeleteRateForHost(ctx context.Context, rateID string) error {
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

	_, err2 := rateCollection.DeleteOne(ctx, filter)
	if err2 != nil {
		span.SetStatus(codes.Error, err.Error())
		rr.logger.Println(err2)
		return err2
	}

	return nil
}
func (rr *AccommodationRepo) UpdateRateForHost(ctx context.Context, rateID string, rate *Rate) error {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.UpdateRateForHost")
	defer span.End()

	rateId, err := primitive.ObjectIDFromHex(rateID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		fmt.Println("Error converting ID to ObjectID:", err)
		return err
	}

	if rate.Rate <= 0 || rate.Rate > 5 {
		span.SetStatus(codes.Error, "Invalid rate value")
		return fmt.Errorf("Invalid rate value: %v. Rate must be between 0 and 5", rate.Rate)
	}

	filter := bson.M{"_id": rateId}
	update := bson.M{"$set": bson.M{"rate": rate.Rate, "updatedAt": rate.UpdatedAt}}

	result, err := rr.getRateCollection(ctx).UpdateOne(ctx, filter, update)

	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		rr.logger.Println("Error updating rate:", err)
		return err
	}

	rr.logger.Printf("Documents matched: %v\n", result.MatchedCount)
	rr.logger.Printf("Documents updated: %v\n", result.ModifiedCount)

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
		span.SetStatus(codes.Error, err.Error())
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
		span.SetStatus(codes.Error, err.Error())
		fmt.Println("Error converting ID to ObjectID:", owner, err)
		return err
	}

	accommodationsCollection := rr.getCollection(ctx)

	filter := bson.M{"ownerId": ownerID}

	_, err2 := accommodationsCollection.DeleteMany(ctx, filter)
	if err2 != nil {
		span.SetStatus(codes.Error, err2.Error())
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
		span.SetStatus(codes.Error, err.Error())
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
		span.SetStatus(codes.Error, err.Error())
		return false, err
	}

	return count > 0, nil
}

func (rr *AccommodationRepo) filterIDs(ctx context.Context, filter interface{}) ([]primitive.ObjectID, error) {
	ctx, span := rr.tracer.Start(ctx, "AccommodationRepo.filterIDs")
	defer span.End()

	accommodationCollection := rr.getCollection(ctx)
	cursor, err := accommodationCollection.Find(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	defer cursor.Close(ctx)

	var accommodationIDs []primitive.ObjectID
	for cursor.Next(ctx) {
		var accommodation Accommodation
		if err := cursor.Decode(&accommodation); err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		accommodationIDs = append(accommodationIDs, accommodation.ID)
	}

	if err := cursor.Err(); err != nil {
		span.SetStatus(codes.Error, err.Error())
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
		span.SetStatus(codes.Error, err.Error())
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
		span.SetStatus(codes.Error, err.Error())
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
