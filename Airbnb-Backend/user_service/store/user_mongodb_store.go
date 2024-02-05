package store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"user_service/domain"
)

const (
	DATABASE               = "user"
	COLLECTION             = "users"
	ErrorParsing           = "Error parsing string to ObjectID:"
	ErrorDecodingResponse  = "Error decoding reservation response:"
	ErrorDecodingResponse2 = "Error decoding reservation response"
)

var (
	reservationServiceHost   = os.Getenv("RESERVATIONS_SERVICE_HOST")
	reservationServicePort   = os.Getenv("RESERVATIONS_SERVICE_PORT")
	accommodationServiceHost = os.Getenv("ACCOMMODATIONS_SERVICE_HOST")
	accommodationServicePort = os.Getenv("ACCOMMODATIONS_SERVICE_PORT")
)

type UserMongoDBStore struct {
	users  *mongo.Collection
	tracer trace.Tracer
}

func NewUserMongoDBStore(client *mongo.Client, tracer trace.Tracer) domain.UserStore {
	users := client.Database(DATABASE).Collection(COLLECTION)
	return &UserMongoDBStore{
		users:  users,
		tracer: tracer,
	}
}

func (store *UserMongoDBStore) Register(ctx context.Context, user *domain.User) (*domain.User, error) {
	ctx, span := store.tracer.Start(ctx, "UserMongoDBStore.Register")
	defer span.End()
	user.Highlighted = false

	fmt.Println(json.Marshal(user))
	user.ID = primitive.NewObjectID()
	result, err := store.users.InsertOne(context.TODO(), user)
	if err != nil {
		span.SetStatus(codes.Error, "Error register user")
		return nil, err
	}
	user.ID = result.InsertedID.(primitive.ObjectID)
	return user, nil
}

func (store *UserMongoDBStore) GetAll(ctx context.Context) ([]*domain.User, error) {
	ctx, span := store.tracer.Start(ctx, "UserMongoDBStore.GetAll")
	defer span.End()

	filter := bson.D{{}}
	return store.filter(ctx, filter)
}

func (store *UserMongoDBStore) Get(ctx context.Context, id primitive.ObjectID) (*domain.User, error) {
	ctx, span := store.tracer.Start(ctx, "UserMongoDBStore.Get")
	defer span.End()

	filter := bson.M{"_id": id}
	return store.filterOne(ctx, filter)
}

func (store *UserMongoDBStore) GetOneUser(ctx context.Context, username string) (*domain.User, error) {
	ctx, span := store.tracer.Start(ctx, "UserMongoDBStore.GetOneUser")
	defer span.End()

	filter := bson.M{"username": username}

	user, err := store.filterOne(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, "Error getting user")
		return nil, err
	}

	return user, nil
}

func (store *UserMongoDBStore) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	ctx, span := store.tracer.Start(ctx, "UserMongoDBStore.GetByEmail")
	defer span.End()

	filter := bson.M{"email": email}
	return store.filterOne(ctx, filter)
}

func (store *UserMongoDBStore) UpdateUserUsername(ctx context.Context, user *domain.User) error {
	ctx, span := store.tracer.Start(ctx, "UserMongoDBStore.UpdateUserUsername")
	defer span.End()

	fmt.Println(user)
	newState, err := store.users.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": user})
	if err != nil {
		span.SetStatus(codes.Error, "Error update user username")
		return err
	}
	fmt.Println(newState)
	return nil
}

func (store *UserMongoDBStore) UpdateUser(ctx context.Context, updateUser *domain.User) (*domain.User, error) {
	ctx, span := store.tracer.Start(ctx, "UserMongoDBStore.UpdateUser")
	defer span.End()

	updateData := bson.M{
		"firstName": updateUser.Firstname,
		"lastName":  updateUser.Lastname,
		"gender":    updateUser.Gender,
		"age":       updateUser.Age,
		"residence": updateUser.Residence,
		"email":     updateUser.Email,
	}

	filter := bson.M{"_id": updateUser.ID}
	update := bson.M{"$set": updateData}

	result, err := store.users.UpdateOne(ctx, filter, update)
	if err != nil {
		span.SetStatus(codes.Error, "Error update user")
		return nil, err
	}

	if result.ModifiedCount == 0 {
		return nil, errors.New("No user updated")
	}

	return updateUser, nil
}

func (store *UserMongoDBStore) IsHighlighted(ctx context.Context, host string, authToken string) (bool, error) {
	ctx, span := store.tracer.Start(ctx, "UserMongoDBStore.IsHighlighted")
	defer span.End()

	accommodationEndpoint := fmt.Sprintf("https://%s:%s/averageRate/%s", accommodationServiceHost, accommodationServicePort, host)
	accommodationResponse, err := store.HTTPSRequestWithouthBody(ctx, authToken, accommodationEndpoint, "GET")
	if err != nil {
		span.SetStatus(codes.Error, "Error sending accommodation request")
		fmt.Println("Error sending accommodation request:", err)
		return false, err
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Accommodation service returned an error")
		fmt.Println("Accommodation service returned an error:", accommodationResponse.Status)
		return false, errors.New("Accommodation service returned an error")
	}

	type AccommodationResponseRate struct {
		AverageRate float64 `json:"averageRate"`
	}

	var response AccommodationResponseRate

	//err = responseToType(accommodationResponse.Body, accommodations)
	err = json.NewDecoder(accommodationResponse.Body).Decode(&response)
	if err != nil {
		span.SetStatus(codes.Error, "Error decoding accommodation response")
		fmt.Println("Error decoding accommodation response:", err)
		return false, err
	}

	defer accommodationResponse.Body.Close()

	reservationEndpoint := fmt.Sprintf("https://%s:%s/cancellationRate/%s", reservationServiceHost, reservationServicePort, host)
	reservationResponse, err := store.HTTPSRequestWithouthBody(ctx, authToken, reservationEndpoint, "GET")
	if err != nil {
		span.SetStatus(codes.Error, "Error sending reservation request")
		fmt.Println("Error sending reservation request:", err)
		return false, err
	}

	if reservationResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Reservation service returned an error")
		fmt.Println("Reservation service returned an error:", reservationResponse.Status)
		return false, errors.New("Reservation service returned an error")
	}

	type ReservationResponseRate struct {
		CancellationRate bool `json:"isBelowThreshold"`
	}

	var response2 ReservationResponseRate

	//err = responseToType(accommodationResponse.Body, accommodations)
	err = json.NewDecoder(reservationResponse.Body).Decode(&response2)
	if err != nil {
		span.SetStatus(codes.Error, ErrorDecodingResponse2)
		fmt.Println(ErrorDecodingResponse, err)
		return false, err
	}

	defer reservationResponse.Body.Close()

	reservationEndpoint2 := fmt.Sprintf("https://%s:%s/numOfReservations/%s", reservationServiceHost, reservationServicePort, host)
	reservationResponse2, err := store.HTTPSRequestWithouthBody(ctx, authToken, reservationEndpoint2, "GET")
	if err != nil {
		span.SetStatus(codes.Error, "Error sending reservation request")
		fmt.Println("Error sending reservation request:", err)
		return false, err
	}

	if reservationResponse2.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Reservation service returned an error")
		fmt.Println("Reservation service returned an error:", reservationResponse2.Status)
		return false, errors.New("Reservation service returned an error")
	}

	type NumOfReservationResponse struct {
		NumOfReservations bool `json:"hasEnoughReservations"`
	}

	var response3 NumOfReservationResponse

	//err = responseToType(accommodationResponse.Body, accommodations)
	err = json.NewDecoder(reservationResponse2.Body).Decode(&response3)
	if err != nil {
		span.SetStatus(codes.Error, ErrorDecodingResponse2)
		fmt.Println(ErrorDecodingResponse, err)
		return false, err
	}

	defer reservationResponse2.Body.Close()

	reservationEndpoint3 := fmt.Sprintf("https://%s:%s/durationOfReservations/%s", reservationServiceHost, reservationServicePort, host)
	reservationResponse3, err := store.HTTPSRequestWithouthBody(ctx, authToken, reservationEndpoint3, "GET")
	if err != nil {
		span.SetStatus(codes.Error, "Error sending reservation request")
		fmt.Println("Error sending reservation request:", err)
		return false, err
	}

	if reservationResponse3.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Reservation service returned an error")
		fmt.Println("Reservation service returned an error:", reservationResponse3.Status)
		return false, errors.New("Reservation service returned an error")
	}

	type DurationOfReservationResponse struct {
		DurationOfReservations bool `json:"hasMoreThan50Days"`
	}

	var response4 DurationOfReservationResponse

	//err = responseToType(accommodationResponse.Body, accommodations)
	err = json.NewDecoder(reservationResponse3.Body).Decode(&response4)
	if err != nil {
		span.SetStatus(codes.Error, ErrorDecodingResponse2)
		fmt.Println(ErrorDecodingResponse, err)
		return false, err
	}

	defer reservationResponse3.Body.Close()

	if response.AverageRate > 4.7 &&
		response2.CancellationRate &&
		response3.NumOfReservations &&
		response4.DurationOfReservations {
		hostID, err := primitive.ObjectIDFromHex(host)
		if err != nil {
			span.SetStatus(codes.Error, ErrorParsing)
			fmt.Println(ErrorParsing, err)
			return false, err
		}
		filter := bson.M{"_id": hostID}

		user, err := store.filterOne(ctx, filter)
		if err != nil {
			span.SetStatus(codes.Error, "Error getting user")
			return false, err
		}

		if user.Highlighted != true {
			updateData := bson.M{
				"highlighted": true,
			}

			filter = bson.M{"_id": hostID}
			update := bson.M{"$set": updateData}

			result, err := store.users.UpdateOne(ctx, filter, update)
			if err != nil {
				span.SetStatus(codes.Error, "Error update user")
				fmt.Println("Error update user")
				return false, err
			}

			if result.ModifiedCount == 0 {
				return false, errors.New("No user updated")
			}
		}
	} else if response.AverageRate < 4.7 ||
		!response2.CancellationRate ||
		!response3.NumOfReservations ||
		!response4.DurationOfReservations {
		hostID, err := primitive.ObjectIDFromHex(host)
		if err != nil {
			span.SetStatus(codes.Error, ErrorParsing)
			fmt.Println(ErrorParsing, err)
			return false, err
		}
		filter := bson.M{"_id": hostID}

		user, err := store.filterOne(ctx, filter)
		if err != nil {
			span.SetStatus(codes.Error, "Error getting user")
			return false, err
		}

		if user.Highlighted != false {
			updateData := bson.M{
				"highlighted": false,
			}

			filter = bson.M{"_id": hostID}
			update := bson.M{"$set": updateData}

			result, err := store.users.UpdateOne(ctx, filter, update)
			if err != nil {
				span.SetStatus(codes.Error, "Error update user")
				fmt.Println("Error update user")
				return false, err
			}

			if result.ModifiedCount == 0 {
				return false, errors.New("No user updated")
			}
		}
	}

	return response.AverageRate > 4.7 &&
		response2.CancellationRate &&
		response3.NumOfReservations &&
		response4.DurationOfReservations, nil
}

func (store *UserMongoDBStore) DeleteAccount(ctx context.Context, userID primitive.ObjectID) error {
	ctx, span := store.tracer.Start(ctx, "UserMongoDBStore.DeleteAccount")
	defer span.End()

	filter := bson.M{"_id": userID}
	result, err := store.users.DeleteOne(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, "Error deleting user")
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("No user deleted")
	}

	return nil
}

func (store *UserMongoDBStore) filter(ctx context.Context, filter interface{}) ([]*domain.User, error) {
	ctx, span := store.tracer.Start(ctx, "UserMongoDBStore.filter")
	defer span.End()

	cursor, err := store.users.Find(ctx, filter)
	defer cursor.Close(ctx)

	if err != nil {
		span.SetStatus(codes.Error, "No user found for the given filter")
		return nil, err
	}
	return decode(cursor)
}

func (store *UserMongoDBStore) filterOne(ctx context.Context, filter interface{}) (user *domain.User, err error) {
	ctx, span := store.tracer.Start(ctx, "UserMongoDBStore.filterOne")
	defer span.End()

	result := store.users.FindOne(ctx, filter)
	err = result.Decode(&user)
	return
}

func decode(cursor *mongo.Cursor) (users []*domain.User, err error) {
	for cursor.Next(context.TODO()) {
		var user domain.User
		err = cursor.Decode(&user)
		if err != nil {
			return
		}
		users = append(users, &user)
	}
	err = cursor.Err()
	return
}

func (store *UserMongoDBStore) HTTPSRequestWithouthBody(ctx context.Context, token string, url string, method string) (*http.Response, error) {
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
