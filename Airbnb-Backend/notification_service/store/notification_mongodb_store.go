package store

import (
	"context"
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel/trace"
	"notification_service/domain"
)

const (
	DATABASE   = "notification"
	COLLECTION = "notifications"
)

type NotificationMongoDBStore struct {
	notifications *mongo.Collection
	tracer        trace.Tracer
}

func NewNotificationMongoDBStore(client *mongo.Client, tracer trace.Tracer) domain.NotificationStore {
	notifications := client.Database(DATABASE).Collection(COLLECTION)
	return &NotificationMongoDBStore{
		notifications: notifications,
		tracer:        tracer,
	}
}

func (store *NotificationMongoDBStore) CreateNotification(ctx context.Context, notification *domain.Notification) (*domain.Notification, error) {
	ctx, span := store.tracer.Start(ctx, "NotificationMongoDBStore.CreateNotification")
	defer span.End()

	fmt.Println(json.Marshal(notification))
	notification.ID = primitive.NewObjectID()
	result, err := store.notifications.InsertOne(context.TODO(), notification)
	if err != nil {
		return nil, err
	}
	notification.ID = result.InsertedID.(primitive.ObjectID)
	return notification, nil
}

func (store *NotificationMongoDBStore) GetAllNotifications(ctx context.Context) ([]*domain.Notification, error) {
	ctx, span := store.tracer.Start(ctx, "NotificationMongoDBStore.GetAllNotifications")
	defer span.End()

	filter := bson.D{{}}
	return store.filter(filter)
}

func (store *NotificationMongoDBStore) GetNotificationsByHostId(ctx context.Context, hostId string) ([]*domain.Notification, error) {
	ctx, span := store.tracer.Start(ctx, "NotificationMongoDBStore.GetNotificationsByHostId")
	defer span.End()

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
