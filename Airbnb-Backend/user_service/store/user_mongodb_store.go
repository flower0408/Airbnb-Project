package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"user_service/domain"
)

const (
	DATABASE   = "user"
	COLLECTION = "users"
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
