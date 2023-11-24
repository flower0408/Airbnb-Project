package data

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log"
	"os"
	"time"
)

type AccommodationRepo struct {
	cli    *mongo.Client
	logger *log.Logger
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

	// Return repository with logger and DB client
	return &AccommodationRepo{
		cli:    client,
		logger: logger,
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

func (rr *AccommodationRepo) InsertAccommodation(accommodation *Accommodation) error {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accommodationCollection := rr.getCollection()

	result, err := accommodationCollection.InsertOne(ctx, &accommodation)
	if err != nil {
		rr.logger.Println(err)
		return err
	}
	rr.logger.Printf("Documents ID: %v\n", result.InsertedID)
	return nil
}

func (rr *AccommodationRepo) getCollection() *mongo.Collection {
	appointmentDatabase := rr.cli.Database("MongoDatabase")
	appointmentsCollection := appointmentDatabase.Collection("accommodations")
	return appointmentsCollection
}

func (rr *AccommodationRepo) GetAll() ([]*Accommodation, error) {
	filter := bson.D{{}}
	return rr.filter(filter)
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
