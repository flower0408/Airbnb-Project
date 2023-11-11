package data

import (
	"encoding/json"
	"github.com/gocql/gocql"
	"io"
)

type Accommodation struct {
	ID          gocql.UUID `json:"id" db:"accommodation_id"`
	Name        string     `json:"name" db:"accommodation_name"`
	Description string     `json:"description" db:"accommodation_description"`
	Images      string     `json:"images" db:"accommodation_images"`
	Location    Location   `json:"location" db:"-"`
	Benefits    string     `json:"benefits" db:"accommodation_benefits"`
	MinGuest    int        `json:"minGuest" db:"minGuest"`
	MaxGuest    int        `json:"maxGuest" db:"maxGuest"`
	OwnerId     gocql.UUID `json:"ownerId" db:"ownerId"`
}

type Location struct {
	Country string `json:"country" db:"country"`
	City    string `json:"city" db:"city"`
	Street  string `json:"street" db:"street"`
	Number  int    `json:"numberr" db:"numberr"`
}

func (o *Accommodation) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(o)
}

func (o *Accommodation) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(o)
}
