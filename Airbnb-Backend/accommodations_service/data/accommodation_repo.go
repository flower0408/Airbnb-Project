package data

import (
	"fmt"
	"log"
	"os"

	// NoSQL: module containing Cassandra api client
	"github.com/gocql/gocql"
)

type AccommodationRepo struct {
	session *gocql.Session
	logger  *log.Logger
}

func New(logger *log.Logger) (*AccommodationRepo, error) {
	db := os.Getenv("ACCOMMODATIONS_DB_HOST")

	// Connect to default keyspace
	cluster := gocql.NewCluster(db)
	cluster.Keyspace = "system"
	session, err := cluster.CreateSession()
	if err != nil {
		logger.Println(err)
		return nil, err
	}

	// Create 'accommodation' keyspace
	err = session.Query(
		fmt.Sprintf(`CREATE KEYSPACE IF NOT EXISTS %s
					WITH replication = {
						'class' : 'SimpleStrategy',
						'replication_factor' : %d
					}`, "accommodation", 1)).Exec()
	if err != nil {
		logger.Println(err)
	}
	session.Close()

	// Connect to accommodation keyspace
	cluster.Keyspace = "accommodation"
	cluster.Consistency = gocql.One
	session, err = cluster.CreateSession()
	if err != nil {
		logger.Println(err)
		return nil, err
	}

	// Return repository with logger and DB session
	return &AccommodationRepo{
		session: session,
		logger:  logger,
	}, nil
}

// Disconnect from database
func (sr *AccommodationRepo) CloseSession() {
	sr.session.Close()
}

// Create tables
func (sr *AccommodationRepo) CreateTables() {

	err := sr.session.Query(
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s 
					(country text, accommodation_id UUID, accommodation_name text, accommodation_description text, accommodation_images text, accommodation_benefits text, minGuest int, maxGuest int, city text, street text, numberr int, ownerId UUID,
					PRIMARY KEY ((country), accommodation_id, maxGuest)) 
					WITH CLUSTERING ORDER BY (accommodation_id ASC, maxGuest DESC)`, "accommodations_by_country")).Exec()
	if err != nil {
		sr.logger.Println(err)
	}

}

func (sr *AccommodationRepo) InsertAccommodation(accommodation *Accommodation) error {

	accommodationId, _ := gocql.RandomUUID()
	err := sr.session.Query(
		`INSERT INTO accommodations_by_country (country, accommodation_id, accommodation_name, accommodation_description, accommodation_images, accommodation_benefits, minGuest, maxGuest, city, street, numberr, ownerId) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		accommodation.Location.Country, accommodationId, accommodation.Name, accommodation.Description, accommodation.Images, accommodation.Benefits, accommodation.MinGuest,
		accommodation.MaxGuest, accommodation.Location.City, accommodation.Location.Street, accommodation.Location.Number, accommodation.OwnerId).Exec()
	if err != nil {
		sr.logger.Println(err)
		return err
	}
	return nil
}

// NoSQL: Performance issue, we never want to fetch all the data
// (In order to get all student ids we need to contact every partition which are usually located on different servers!)
// Here we are doing it for demonstration purposes (so we can see all student/predmet ids)
func (sr *AccommodationRepo) GetDistinctIds(idColumnName string, tableName string) ([]string, error) {
	scanner := sr.session.Query(
		fmt.Sprintf(`SELECT DISTINCT %s FROM %s`, idColumnName, tableName)).
		Iter().Scanner()
	var ids []string
	for scanner.Next() {
		var id string
		err := scanner.Scan(&id)
		if err != nil {
			sr.logger.Println(err)
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := scanner.Err(); err != nil {
		sr.logger.Println(err)
		return nil, err
	}
	return ids, nil
}
