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
	"os"
	"time"
)

type AppointmentRepo struct {
	cli    *mongo.Client
	logger *log.Logger
}

func NewAppointmentRepo(ctx context.Context, logger *log.Logger) (*AppointmentRepo, error) {
	dburi := fmt.Sprintf("mongodb://%s:%s/", os.Getenv("APPOINTMENTS_DB_HOST"), os.Getenv("APPOINTMENTS_DB_PORT"))

	client, err := mongo.NewClient(options.Client().ApplyURI(dburi))
	if err != nil {
		return nil, err
	}

	err = client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	// Return repository with logger and DB client
	return &AppointmentRepo{
		logger: logger,
		cli:    client,
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
func (rr *AppointmentRepo) InsertAppointment(appointment *Appointment) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	appointmentsCollection := rr.getCollection()

	result, err := appointmentsCollection.InsertOne(ctx, &appointment)
	if err != nil {
		rr.logger.Println(err)
		return err
	}
	rr.logger.Printf("Documents ID: %v\n", result.InsertedID)
	return nil
}

func (rr *AppointmentRepo) UpdateAppointment(id string, appointment *Appointment) error {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	appointmentsCollection := rr.getCollection()

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		rr.logger.Println("Error converting ID to ObjectID:", err)
		return err
	}

	filter := bson.M{"_id": objectID}
	update := bson.M{"$set": bson.M{
		"available": appointment.Available,
	}}

	result, err := appointmentsCollection.UpdateOne(ctx, filter, update)
	rr.logger.Printf("Documents matched: %v\n", result.MatchedCount)
	rr.logger.Printf("Documents updated: %v\n", result.ModifiedCount)

	if err != nil {
		rr.logger.Println(err)
		return err
	}
	return nil
}

func (rr *AppointmentRepo) GetAppointmentByID(id string) (*Appointment, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	appointmentsCollection := rr.getCollection()

	var appointment Appointment
	objID, _ := primitive.ObjectIDFromHex(id)
	err := appointmentsCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&appointment)
	if err != nil {
		rr.logger.Println(err)
		return nil, err
	}
	return &appointment, nil
}

func (rr *AppointmentRepo) AddPriceForIntervalForAppointment(id string, priceForInterval *PriceForInterval) error {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	appointmentsCollection := rr.getCollection()

	objID, _ := primitive.ObjectIDFromHex(id)
	priceForInterval.ID = primitive.NewObjectID()

	filter := bson.M{"_id": objID}
	update := bson.M{"$push": bson.M{
		"priceForInterval": priceForInterval,
	}}

	result, err := appointmentsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		rr.logger.Println(err)
		return err
	}
	if result.ModifiedCount == 0 {
		return errors.New("No document updated")
	}

	rr.logger.Printf("Documents matched: %v\n", result.MatchedCount)
	rr.logger.Printf("Documents updated: %v\n", result.ModifiedCount)

	return nil
}

func (rr *AppointmentRepo) EditPriceForIntervalForAppointment(id string, intervalId string, priceForInterval *PriceForInterval) error {

	//TODO
	return nil
}

func (rr *AppointmentRepo) getCollection() *mongo.Collection {
	appointmentDatabase := rr.cli.Database("MongoDatabase")
	appointmentsCollection := appointmentDatabase.Collection("appointments")
	return appointmentsCollection
}
