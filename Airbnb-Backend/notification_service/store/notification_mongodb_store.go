package store

import (
	"context"
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"notification_service/domain"
)

const (
	DATABASE   = "notification"
	COLLECTION = "notifications"
)

type NotificationMongoDBStore struct {
	notifications *mongo.Collection
}

func NewNotificationMongoDBStore(client *mongo.Client) domain.NotificationStore {
	notifications := client.Database(DATABASE).Collection(COLLECTION)
	return &NotificationMongoDBStore{
		notifications: notifications,
	}
}

func (store *NotificationMongoDBStore) CreateNotification(notification *domain.Notification) (*domain.Notification, error) {
	fmt.Println(json.Marshal(notification))
	notification.ID = primitive.NewObjectID()
	result, err := store.notifications.InsertOne(context.TODO(), notification)
	if err != nil {
		return nil, err
	}
	notification.ID = result.InsertedID.(primitive.ObjectID)
	return notification, nil
}

func (store *NotificationMongoDBStore) GetAllNotifications() ([]*domain.Notification, error) {
	filter := bson.D{{}}
	return store.filter(filter)
}

func (store *NotificationMongoDBStore) GetNotificationsByHostId(hostId string) ([]*domain.Notification, error) {
	filter := bson.M{"forHostId": hostId}
	return store.filter(filter)
}

func (store *NotificationMongoDBStore) filter(filter interface{}) ([]*domain.Notification, error) {
	cursor, err := store.notifications.Find(context.TODO(), filter)
	defer cursor.Close(context.TODO())

	if err != nil {
		return nil, err
	}
	return decode(cursor)
}

func (store *NotificationMongoDBStore) filterOne(filter interface{}) (notification *domain.Notification, err error) {
	result := store.notifications.FindOne(context.TODO(), filter)
	err = result.Decode(&notification)
	return
}

func decode(cursor *mongo.Cursor) (users []*domain.Notification, err error) {
	for cursor.Next(context.TODO()) {
		var user domain.Notification
		err = cursor.Decode(&user)
		if err != nil {
			return
		}
		users = append(users, &user)
	}
	err = cursor.Err()
	return
}
