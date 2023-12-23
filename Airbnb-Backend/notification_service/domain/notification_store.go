package domain

type NotificationStore interface {
	GetNotificationsByHostId(hostId string) ([]*Notification, error)
	GetAllNotifications() ([]*Notification, error)
	CreateNotification(user *Notification) (*Notification, error)
}
