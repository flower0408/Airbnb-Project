package domain

import "context"

type NotificationStore interface {
	GetNotificationsByHostId(ctx context.Context, hostId string) ([]*Notification, error)
	GetAllNotifications(ctx context.Context) ([]*Notification, error)
	CreateNotification(ctx context.Context, user *Notification) (*Notification, error)
}
