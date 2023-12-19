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
	"log"
	"net/http"
	"os"
	"time"
)

type AccommodationRepo struct {
	cli    *mongo.Client
	logger *log.Logger
	client *http.Client
}

func New(ctx context.Context, logger *log.Logger) (*AccommodationRepo, error) {
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

func (rr *AccommodationRepo) InsertAccommodation(accommodation *Accommodation) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	accommodationCollection := rr.getCollection()

	result, err := accommodationCollection.InsertOne(ctx, accommodation)
	if err != nil {
		rr.logger.Println(err)
		return "", err
	}

	insertedID, ok := result.InsertedID.(primitive.ObjectID)
	if !ok {
		rr.logger.Println("Failed to convert InsertedID to ObjectID")
		return "", errors.New("Failed to convert InsertedID")
	}

	return insertedID.Hex(), nil
}

func (rr *AccommodationRepo) InsertRateForAccommodation(rate *Rate) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	rateCollection := rr.getRateCollection()

	_, err := rateCollection.InsertOne(ctx, rate)
	if err != nil {
		rr.logger.Println(err)
		return "", err
	}

	return "", nil
}

func (rr *AccommodationRepo) getCollection() *mongo.Collection {
	accommodationDatabase := rr.cli.Database("MongoDatabase")
	accommodationCollection := accommodationDatabase.Collection("accommodations")
	return accommodationCollection
}

func (rr *AccommodationRepo) getRateCollection() *mongo.Collection {
	rateDatabase := rr.cli.Database("MongoDatabase")
	rateCollection := rateDatabase.Collection("rates")
	return rateCollection
}

func (rr *AccommodationRepo) GetAll() ([]*Accommodation, error) {
	filter := bson.D{{}}
	return rr.filter(filter)
}

func (rr *AccommodationRepo) GetAllRate() ([]*Rate, error) {
	filter := bson.D{{}}
	return rr.filterRate(filter)
}

func (rr *AccommodationRepo) GetByID(id primitive.ObjectID) (*Accommodation, error) {
	filter := bson.D{{"_id", id}}
	return rr.getByFilter(filter)
}

func (rr *AccommodationRepo) GetRatesByAccommodation(id string) ([]*Rate, error) {
	filter := bson.D{{"forAccommodationId", id}}
	return rr.filterRate(filter)
}

func (rr *AccommodationRepo) getByFilter(filter interface{}) (*Accommodation, error) {
	ctx := context.TODO()
	accommodationCollection := rr.getCollection()

	var accommodation Accommodation
	err := accommodationCollection.FindOne(ctx, filter).Decode(&accommodation)
	if err != nil {
		return nil, err
	}

	return &accommodation, nil
}

func (rr *AccommodationRepo) Search(filter interface{}) ([]*Accommodation, error) {
	return rr.filter(filter)
}

func (rr *AccommodationRepo) GetAccommodationsByOwner(ownerID string) ([]primitive.ObjectID, error) {
	filter := bson.D{{"ownerId", ownerID}}
	return rr.filterIDs(filter)
}

func (rr *AccommodationRepo) DeleteAccommodationsByOwner(ownerID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	accommodationsCollection := rr.getCollection()

	filter := bson.M{"ownerId": ownerID}

	_, err := accommodationsCollection.DeleteMany(ctx, filter)
	if err != nil {
		rr.logger.Println(err)
		return err
	}

	return nil
}

func (rr *AccommodationRepo) filterIDs(filter interface{}) ([]primitive.ObjectID, error) {
	ctx := context.TODO()
	accommodationCollection := rr.getCollection()
	cursor, err := accommodationCollection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var accommodationIDs []primitive.ObjectID
	for cursor.Next(ctx) {
		var accommodation Accommodation
		if err := cursor.Decode(&accommodation); err != nil {
			return nil, err
		}
		accommodationIDs = append(accommodationIDs, accommodation.ID)
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	return accommodationIDs, nil
}

func (rr *AccommodationRepo) filter(filter interface{}) ([]*Accommodation, error) {
	ctx := context.TODO()
	accommodationCollection := rr.getCollection()
	cursor, err := accommodationCollection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	return decode(cursor)
}

func (rr *AccommodationRepo) filterRate(filter interface{}) ([]*Rate, error) {
	ctx := context.TODO()
	rateCollection := rr.getRateCollection()
	cursor, err := rateCollection.Find(ctx, filter)
	if err != nil {
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
