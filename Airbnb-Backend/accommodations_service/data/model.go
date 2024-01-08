package data

import (
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
)

type Accommodation struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name        string             `bson:"name,omitempty" json:"name"`
	Description string             `bson:"description,omitempty" json:"description"`
	Images      string             `bson:"images,omitempty" json:"images"`
	Location    Location           `bson:"location,omitempty" json:"location"`
	Benefits    string             `bson:"benefits,omitempty" json:"benefits"`
	MinGuest    int                `bson:"minGuest,omitempty" json:"minGuest"`
	MaxGuest    int                `bson:"maxGuest,omitempty" json:"maxGuest"`
	OwnerId     string             `bson:"ownerId,omitempty" json:"ownerId"`
}

type Location struct {
	Country string `bson:"country,omitempty" json:"country"`
	City    string `bson:"city,omitempty" json:"city"`
	Street  string `bson:"street,omitempty" json:"street"`
	Number  int    `bson:"number,omitempty" json:"number"`
}

type Rate struct {
	ID                 primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ByGuestId          string             `bson:"byGuestId,omitempty" json:"byGuestId"`
	ForHostId          string             `bson:"forHostId,omitempty" json:"forHostId"`
	ForAccommodationId string             `bson:"forAccommodationId,omitempty" json:"forAccommodationId"`
	CreatedAt          string             `bson:"createdAt,omitempty" json:"createdAt"`
	UpdatedAt          string             `bson:"updatedAt,omitempty" json:"updatedAt"`
	Rate               int                `bson:"rate,omitempty" json:"rate"`
}

type FilterParams struct {
	DesiredBenefits []string `json:"desiredBenefits"`
	MinPrice        string   `json:"minPrice"`
	MaxPrice        string   `json:"maxPrice"`
}

func (o *Accommodation) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(o)
}

func (o *Accommodation) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(o)
}

func (o *Rate) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(o)
}

func (o *Rate) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(o)
}
