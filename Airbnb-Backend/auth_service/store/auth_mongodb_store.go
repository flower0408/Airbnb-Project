package store

import (
	"auth_service/domain"
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
)

const (
	DATABASE   = "user_credentials"
	COLLECTION = "credentials"
)

type AuthMongoDBStore struct {
	credentials *mongo.Collection
}

func NewAuthMongoDBStore(client *mongo.Client) domain.AuthStore {
	auths := client.Database(DATABASE).Collection(COLLECTION)
	return &AuthMongoDBStore{
		credentials: auths,
	}

}
func (store *AuthMongoDBStore) GetAll() ([]*domain.Credentials, error) {
	filter := bson.D{{}}
	return store.filter2(filter)
}

func (store *AuthMongoDBStore) Register(credentials *domain.Credentials) error {
	credentials.ID = primitive.NewObjectID()
	result, err := store.credentials.InsertOne(context.TODO(), credentials)

	if err != nil {
		return err
	}
	credentials.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

func (store *AuthMongoDBStore) GetOneUser(username string) (*domain.Credentials, error) {
	filter := bson.M{"username": username}

	user, err := store.filterOne2(filter)
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

func (store *AuthMongoDBStore) UpdateUserUsername(user *domain.Credentials) error {

	fmt.Println(user)
	newState, err := store.credentials.UpdateOne(context.TODO(), bson.M{"username": user.Username}, bson.M{"$set": user})
	if err != nil {
		return err
	}
	fmt.Println(newState)
	return nil
}

func (store *AuthMongoDBStore) UpdateUser(user *domain.Credentials) error {

	fmt.Println(user)
	newState, err := store.credentials.UpdateOne(context.TODO(), bson.M{"_id": user.ID}, bson.M{"$set": user})
	if err != nil {
		return err
	}
	fmt.Println(newState)
	return nil
}

func (store *AuthMongoDBStore) GetOneUserByID(id primitive.ObjectID) *domain.Credentials {
	filter := bson.M{"_id": id}

	var user domain.Credentials
	err := store.credentials.FindOne(context.TODO(), filter, nil).Decode(&user)
	if err != nil {
		return nil
	}

	return &user
}

func (store *AuthMongoDBStore) filter(filter interface{}) ([]*domain.User, error) {
	ctx := context.TODO()
	cursor, err := store.credentials.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	return decode(cursor)
}

func (store *AuthMongoDBStore) filter2(filter interface{}) ([]*domain.Credentials, error) {
	ctx := context.TODO()
	cursor, err := store.credentials.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	return decode1(cursor)
}

func (store *AuthMongoDBStore) filterOne(filter interface{}) (*domain.User, error) {
	result := store.credentials.FindOne(context.TODO(), filter)

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

func (store *AuthMongoDBStore) filterOne2(filter interface{}) (user *domain.Credentials, err error) {
	result := store.credentials.FindOne(context.TODO(), filter)
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
