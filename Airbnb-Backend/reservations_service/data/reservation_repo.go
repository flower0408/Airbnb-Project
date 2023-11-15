package data

import (
	"fmt"
	"log"
	"os"

	// NoSQL: module containing Cassandra api client
	"github.com/gocql/gocql"
)

type ReservationRepo struct {
	session *gocql.Session
	logger  *log.Logger
}

func NewReservationRepo(logger *log.Logger) (*ReservationRepo, error) {

	db := os.Getenv("RESERVATIONS_DB_HOST")

	// Connect to default keyspace
	cluster := gocql.NewCluster(db)
	cluster.Keyspace = "system"
	session, err := cluster.CreateSession()
	if err != nil {
		logger.Println(err)
		return nil, err
	}

	// Create 'reservation' keyspace
	err = session.Query(
		fmt.Sprintf(`CREATE KEYSPACE IF NOT EXISTS %s
					WITH replication = {
						'class' : 'SimpleStrategy',
						'replication_factor' : %d
					}`, "reservation", 1)).Exec()
	if err != nil {
		logger.Println(err)
	}
	session.Close()

	// Connect to reservation keyspace
	cluster.Keyspace = "reservation"
	cluster.Consistency = gocql.One
	session, err = cluster.CreateSession()
	if err != nil {
		logger.Println(err)
		return nil, err
	}

	// Return repository with logger and DB session
	return &ReservationRepo{
		session: session,
		logger:  logger,
	}, nil
}

// Disconnect from database
func (sr *ReservationRepo) CloseSession() {
	sr.session.Close()
}

// Create tables
func (sr *ReservationRepo) CreateTables() {

	err := sr.session.Query(
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s 
					(by_userId text,reservation_id UUID, periodd LIST<TIMESTAMP>, accommodation_id text, price int,
					PRIMARY KEY ((by_userId), reservation_id)) 
					WITH CLUSTERING ORDER BY (reservation_id ASC)`, "reservation_by_user")).Exec()
	if err != nil {
		sr.logger.Println(err)
	}

}

// cassandra
func (sr *ReservationRepo) InsertReservation(reservation *Reservation) error {

	reservationId, _ := gocql.RandomUUID()

	err := sr.session.Query(
		`INSERT INTO reservation_by_user (by_userId, reservation_id, periodd, accommodation_id, price) 
		VALUES (?, ?, ?, ?, ?)`,
		reservation.ByUserId, reservationId, reservation.Period, reservation.AccommodationId, reservation.Price).Exec()
	if err != nil {
		sr.logger.Println(err)
		return err
	}
	return nil
}

// NoSQL: Performance issue, we never want to fetch all the data
// (In order to get all student ids we need to contact every partition which are usually located on different servers!)
// Here we are doing it for demonstration purposes (so we can see all student/predmet ids)
func (sr *ReservationRepo) GetDistinctIds(idColumnName string, tableName string) ([]string, error) {
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
