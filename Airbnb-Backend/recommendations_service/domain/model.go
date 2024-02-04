package domain

import "time"

type User struct {
	ID       string   `json:"id,omitempty"`
	Username string   `json:"username"`
	UserType UserType `json:"userType"`
}

type UserType string

const (
	Guest = "Guest"
	Host  = "Host"
)

type Accommodation struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	OwnerId string `json:"ownerId"`
}

type Rate struct {
	ID                 string `json:"id,omitempty"`
	Rate               int    `json:"rate"`
	CreatedAt          string `json:"createdAt"`
	UpdatedAt          string `json:"updatedAt"`
	ByGuestId          string `json:"byGuestId"`
	ForAccommodationId string `json:"forAccommodationId"`
}

type Reservation struct {
	ID              string      `json:"id,omitempty"`
	Period          []time.Time `json:"period"`
	ByUserId        string      `json:"byUserId"`
	AccommodationId string      `json:"accommodationId"`
}

type UsernameChange struct {
	OldUsername string `json:"old_username"`
	NewUsername string `json:"new_username"`
}
