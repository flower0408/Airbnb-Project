package data

import (
	"encoding/json"
	"github.com/gocql/gocql"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
	"time"
)

// mongo
type Appointment struct {
	ID                    primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Available             []time.Time        `bson:"available,omitempty" json:"available"`
	AccommodationId       string             `bson:"accommodationId,omitempty" json:"accommodationId"`
	PricePerGuest         int                `bson:"pricePerGuest,omitempty" json:"pricePerGuest"`
	PricePerAccommodation int                `bson:"pricePerAccommodation,omitempty" json:"pricePerAccommodation"`
}

// cassandra
type Reservation struct {
	ID              gocql.UUID  `json:"id" db:"reservation_id"`
	Period          []time.Time `json:"period" db:"periodd"`
	ByUserId        string      `json:"byUserId" db:"by_userId"`
	AccommodationId string      `json:"accommodationId" db:"accommodation_id"`
	Price           int         `json:"price" db:"price"`
	Canceled        bool        `json:"canceled" db:"canceled"`
}

type Appointments []*Appointment
type Reservations []*Reservation

func (o *Appointments) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(o)
}

func (o *Appointments) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(o)
}

func (o *Appointment) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(o)
}

func (o *Appointment) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(o)
}

func (o *Reservation) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(o)
}

func (o *Reservation) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(o)
}

func (o *Reservations) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(o)
}

func (o *Reservations) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(o)
}
