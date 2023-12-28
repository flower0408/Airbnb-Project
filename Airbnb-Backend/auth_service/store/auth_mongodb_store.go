package store

import (
	"auth_service/domain"
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"log"
)

const (
	DATABASE   = "user_credentials"
	COLLECTION = "credentials"
)

type AuthMongoDBStore struct {
	credentials *mongo.Collection
	tracer      trace.Tracer
}

func NewAuthMongoDBStore(client *mongo.Client, tracer trace.Tracer) domain.AuthStore {
	auths := client.Database(DATABASE).Collection(COLLECTION)
	return &AuthMongoDBStore{
		credentials: auths,
		tracer:      tracer,
	}

}
func (store *AuthMongoDBStore) GetAll(ctx context.Context) ([]*domain.Credentials, error) {
	ctx, span := store.tracer.Start(ctx, "AuthStore.GetAll")
	defer span.End()

	filter := bson.D{{}}
	return store.filter2(ctx, filter)
}

func (store *AuthMongoDBStore) Register(ctx context.Context, credentials *domain.Credentials) error {
	ctx, span := store.tracer.Start(ctx, "AuthStore.Register")
	defer span.End()

	credentials.ID = primitive.NewObjectID()
	result, err := store.credentials.InsertOne(context.TODO(), credentials)

	if err != nil {
		return err
	}
	credentials.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

func (store *AuthMongoDBStore) GetOneUser(ctx context.Context, username string) (*domain.Credentials, error) {
	ctx, span := store.tracer.Start(ctx, "AuthStore.GetOneUser")
	defer span.End()
	filter := bson.M{"username": username}

	user, err := store.filterOne2(ctx, filter)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// No user found, return nil without an error
			return nil, nil
		}
		log.Println("Error fetching user:", err)
		return nil, err
	}

	log.Println("Retrieved user:", user)

	return user, nil
}

func (store *AuthMongoDBStore) UpdateUserUsername(ctx context.Context, user *domain.Credentials) error {
	ctx, span := store.tracer.Start(ctx, "AuthStore.UpdateUserUsername")
	defer span.End()

	fmt.Println(user)
	newState, err := store.credentials.UpdateOne(ctx, bson.M{"username": user.Username}, bson.M{"$set": user})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	fmt.Println(newState)
	return nil
}

func (store *AuthMongoDBStore) UpdateUser(ctx context.Context, user *domain.Credentials) error {
	ctx, span := store.tracer.Start(ctx, "AuthStore.UpdateUser")
	defer span.End()

	fmt.Println(user)
	newState, err := store.credentials.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": user})
	if err != nil {
		return err
	}
	fmt.Println(newState)
	return nil
}

func (store *AuthMongoDBStore) DeleteUser(ctx context.Context, username string) error {
	ctx, span := store.tracer.Start(ctx, "AuthStore.DeleteUser")
	defer span.End()

	filter := bson.M{"username": username}
	_, err := store.credentials.DeleteOne(ctx, filter)
	if err != nil {
		return err
	}
	return nil
}

func (store *AuthMongoDBStore) GetOneUserByID(ctx context.Context, id primitive.ObjectID) *domain.Credentials {
	ctx, span := store.tracer.Start(ctx, "AuthStore.GetOneUserByID")
	defer span.End()

	filter := bson.M{"_id": id}

	var user domain.Credentials
	err := store.credentials.FindOne(ctx, filter, nil).Decode(&user)
	if err != nil {
		return nil
	}

	return &user
}

func (store *AuthMongoDBStore) filter(ctx context.Context, filter interface{}) ([]*domain.User, error) {
	cursor, err := store.credentials.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	return decode(cursor)
}

func (store *AuthMongoDBStore) filter2(ctx context.Context, filter interface{}) ([]*domain.Credentials, error) {
	cursor, err := store.credentials.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	return decode1(cursor)
}

func (store *AuthMongoDBStore) filterOne(ctx context.Context, filter interface{}) (*domain.User, error) {
	result := store.credentials.FindOne(ctx, filter)

	var user domain.User
	if err := result.Decode(&user); err != nil {
		if err == mongo.ErrNoDocuments {
			log.Println("No user found for the given filter")
			return nil, nil
		}
		log.Println("Error decoding user:", err)
		return nil, err
	}

	return &user, nil
}

func (store *AuthMongoDBStore) filterOne2(ctx context.Context, filter interface{}) (user *domain.Credentials, err error) {
	result := store.credentials.FindOne(ctx, filter)
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

func decode1(cursor *mongo.Cursor) (users []*domain.Credentials, err error) {
	for cursor.Next(context.TODO()) {
		var user domain.Credentials
		err = cursor.Decode(&user)
		if err != nil {
			return
		}
		users = append(users, &user)
	}
	err = cursor.Err()
	return
}
