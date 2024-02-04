package store

import (
	"context"
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"go.opentelemetry.io/otel/trace"
	"log"
	"recommendations_service/domain"
	"recommendations_service/errors"
)

const (
	DATABASE = "recommendation"
)

type RecommendationNeo4JStore struct {
	driver neo4j.DriverWithContext
	logger *log.Logger
	tracer trace.Tracer
}

func NewRecommendationNeo4JStore(driver *neo4j.DriverWithContext, tracer trace.Tracer) domain.RecommendationStore {
	return &RecommendationNeo4JStore{
		driver: *driver,
		logger: log.Default(),
		tracer: tracer,
	}
}

func (store *RecommendationNeo4JStore) CreateAccommodation(ctx context.Context, accommodation *domain.Accommodation) error {
	ctx, span := store.tracer.Start(ctx, "RecommendationStore.CreateAccommodation")
	defer span.End()

	log.Println("RecommendationStore.CreateAccommodation : CreateAccommodation reached")

	session := store.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: DATABASE})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx,
		func(transaction neo4j.ManagedTransaction) (any, error) {
			result, err := transaction.Run(ctx,
				"CREATE (a:Accommodation) SET a.id = $id, a.name = $name, "+
					"a.ownerId = $ownerId RETURN a.id + ', from node ' + id(a)",
				map[string]any{"id": accommodation.ID, "name": accommodation.Name, "ownerId": accommodation.OwnerId})
			if err != nil {
				log.Printf("RecommendationStore.CreateAccommodation.Run() : %s", err)
				return nil, err
			}

			if result.Next(ctx) {
				return result.Record().Values[0], nil
			}

			return nil, result.Err()
		})
	if err != nil {
		log.Printf("RecommendationStore.CreateAccommodation.ExecuteWrite() : %s\n", err)
		return err
	}

	log.Println("RecommendationStore.CreateAccommodation : CreateAccommodation successful")

	return nil
}

func (store *RecommendationNeo4JStore) DeleteAccommodation(ctx context.Context, id *string) error {
	ctx, span := store.tracer.Start(ctx, "RecommendationStore.DeleteAccommodation")
	defer span.End()

	log.Printf("RecommendationStore.DeleteAccommodation : DeleteAccommodation reached")

	session := store.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: DATABASE})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		_, err := transaction.Run(ctx,
			"MATCH (a:Accommodation) "+
				"WHERE a.id = $id "+
				"DELETE a",
			map[string]any{"id": id})
		if err != nil {
			log.Printf("RecommendationStore.DeleteAccommodation.Run() : %s", err)
			return nil, err
		}

		return nil, nil
	})

	if err != nil {
		log.Printf("RecommendationStore.DeleteAccommodation.ExecuteWrite() : %s", err)

		return err
	}

	log.Printf("RecommendationStore.DeleteAccommodation : DeleteAccommodation successful")

	return nil
}

func (store *RecommendationNeo4JStore) CreateRate(ctx context.Context, rate *domain.Rate) error {
	ctx, span := store.tracer.Start(ctx, "RecommendationStore.CreateRate")
	defer span.End()

	log.Println("RecommendationStore.CreateRate : CreateRate reached")

	session := store.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: DATABASE})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx,
		func(transaction neo4j.ManagedTransaction) (any, error) {
			result, err := transaction.Run(ctx,
				"CREATE (r:Rate) SET r.id = $id, r.rate = $rate, "+
					"r.createdAt = $createdAt, r.updatedAt = $updatedAt, r.byGuestId = $byGuestId, r.forAccommodationId = $forAccommodationId  RETURN r.id + ', from node ' + id(r)",
				map[string]any{"id": rate.ID, "rate": rate.Rate, "createdAt": rate.CreatedAt, "updatedAt": rate.UpdatedAt, "byGuestId": rate.ByGuestId, "forAccommodationId": rate.ForAccommodationId})
			if err != nil {
				log.Printf("RecommendationStore.CreateRate.Run() : %s", err)
				return nil, err
			}

			if result.Next(ctx) {
				return result.Record().Values[0], nil
			}

			return nil, result.Err()
		})
	if err != nil {
		log.Printf("RecommendationStore.CreateRate.ExecuteWrite() : %s\n", err)
		return err
	}

	log.Println("RecommendationStore.CreateRate : CreateRate successful")

	return nil
}

func (store *RecommendationNeo4JStore) DeleteRate(ctx context.Context, id *string) error {
	ctx, span := store.tracer.Start(ctx, "RecommendationStore.DeleteRate")
	defer span.End()

	log.Printf("RecommendationStore.DeleteRate : DeleteRate reached")

	session := store.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: DATABASE})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		_, err := transaction.Run(ctx,
			"MATCH (r:Rate) "+
				"WHERE r.id = $id "+
				"DELETE r",
			map[string]any{"id": id})
		if err != nil {
			log.Printf("RecommendationStore.DeleteRate.Run() : %s", err)
			return nil, err
		}

		return nil, nil
	})

	if err != nil {
		log.Printf("RecommendationStore.DeleteRate.ExecuteWrite() : %s", err)

		return err
	}

	log.Printf("RecommendationStore.DeleteRate : DeleteRate successful")

	return nil
}

func (store *RecommendationNeo4JStore) UpdateRate(ctx context.Context, rate *domain.Rate) (*domain.Rate, error) {
	ctx, span := store.tracer.Start(ctx, "RecommendationStore.UpdateRate")
	defer span.End()

	log.Printf("RecommendationStore.UpdateRate: UpdateRate reached")

	session := store.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: DATABASE})
	defer session.Close(ctx)

	request, err := session.ExecuteWrite(ctx,
		func(transaction neo4j.ManagedTransaction) (interface{}, error) {
			result, err := transaction.Run(ctx,
				"MATCH (rate:Rate) "+
					"WHERE rate.id = $id "+
					"SET rate.rate = $rate, rate.updatedAt = $updatedAt "+
					"RETURN rate.id as id, rate.rate as rate, rate.updatedAt as updatedAt",

				map[string]interface{}{"id": rate.ID, "rate": rate.Rate, "updatedAt": rate.UpdatedAt})
			if err != nil {
				log.Printf("RecommendationStore.UpdateRate.Run(): %s", err)
				return nil, err
			}

			var updatedRate *domain.Rate
			if result.Next(ctx) {
				record := result.Record()
				id, _ := record.Get("id")
				rateInt64, _ := record.Get("rate")
				updatedAt, _ := record.Get("updatedAt")
				updatedRate = &domain.Rate{
					ID:        id.(string),
					Rate:      int(rateInt64.(int64)),
					UpdatedAt: updatedAt.(string),
				}
			}

			return updatedRate, nil
		})

	if err != nil {
		log.Printf("RecommendationStore.UpdateRate.ExecuteWrite(): %s", err)
		return nil, err
	}

	log.Printf("RecommendationStore.UpdateRate: UpdateRate successful")

	return request.(*domain.Rate), nil
}

func (store *RecommendationNeo4JStore) CreateReservation(ctx context.Context, reservation *domain.Reservation) error {
	ctx, span := store.tracer.Start(ctx, "RecommendationStore.CreateReservation")
	defer span.End()

	log.Println("RecommendationStore.CreateReservation : CreateReservation reached")

	session := store.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: DATABASE})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx,
		func(transaction neo4j.ManagedTransaction) (any, error) {
			result, err := transaction.Run(ctx,
				"CREATE (res:Reservation) SET res.id = $id, res.period = $period, "+
					"res.byUserId = $byUserId, res.accommodationId = $accommodationId "+
					"RETURN res.id + ', from node ' + id(res) AS result",
				map[string]any{"id": reservation.ID, "period": reservation.Period, "byUserId": reservation.ByUserId, "accommodationId": reservation.AccommodationId})
			if err != nil {
				log.Printf("RecommendationStore.CreateReservation.Run() : %s", err)
				return nil, err
			}

			if result.Next(ctx) {
				record := result.Record()
				resultValue, _ := record.Get("result")
				log.Printf("Result: %s", resultValue)
				return resultValue, nil
			}

			return nil, result.Err()
		})
	if err != nil {
		log.Printf("RecommendationStore.CreateReservation.ExecuteWrite() : %s\n", err)
		return err
	}

	log.Println("RecommendationStore.CreateReservation : CreateReservation successful")

	return nil
}

func (store *RecommendationNeo4JStore) GetRecommendAccommodationsId(ctx context.Context, id string) ([]string, error) {
	ctx, span := store.tracer.Start(ctx, "RecommendationStore.GetRecommendAccommodationsId")
	defer span.End()

	session := store.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: DATABASE})
	defer session.Close(ctx)

	result, err := session.Run(ctx,
		"MATCH (targetUser:User {id: $userId})-[:BOOKED]->(targetReservation:Reservation) "+
			"WITH targetUser, COLLECT(DISTINCT targetReservation.accommodationId) AS targetAccommodations "+
			"MATCH (similarUser:User)-[:BOOKED]->(similarReservation:Reservation) "+
			"WHERE targetUser <> similarUser AND similarReservation.accommodationId IN targetAccommodations "+
			"WITH targetUser, similarUser, COLLECT(DISTINCT similarReservation.accommodationId) AS commonAccommodations "+
			"WHERE size(commonAccommodations) >= 2 "+
			"MATCH (recommendedAccommodation:Accommodation) "+
			"WHERE recommendedAccommodation.id IN commonAccommodations "+
			"WITH targetUser, recommendedAccommodation "+
			"MATCH (rate:Rate) "+
			"WHERE rate.forAccommodationId = recommendedAccommodation.id "+
			"WITH targetUser, recommendedAccommodation, rate, COLLECT(rate) AS rates "+
			"WITH targetUser, recommendedAccommodation, AVG(rate.rate) AS avgRating, COUNT(rate) AS totalRatings, "+
			"REDUCE(s = 0, r IN rates | s + CASE WHEN datetime(r.createdAt) >= datetime() - duration({months: 3}) THEN 1 ELSE 0 END) AS recentRatingsCount "+
			"WHERE totalRatings >= 1 AND avgRating >= 3 AND recentRatingsCount <= 5 "+
			"WITH targetUser, recommendedAccommodation, totalRatings, avgRating "+
			"MATCH (similarUser:User)-[:BOOKED]->(similarReservation:Reservation) "+
			"WHERE similarReservation.accommodationId = recommendedAccommodation.id AND similarUser <> targetUser "+
			"WITH targetUser, recommendedAccommodation, totalRatings, avgRating, COUNT(DISTINCT similarUser) AS similarUsersCount "+
			"RETURN recommendedAccommodation.id AS recommendedAccommodationId, totalRatings, avgRating, similarUsersCount "+
			"ORDER BY avgRating DESC "+
			"LIMIT 10;",
		map[string]interface{}{"userId": id})
	if err != nil {
		return nil, err
	}

	var recommendedAccommodations []string
	for result.Next(ctx) {
		record := result.Record()
		accommodationID, found := record.Get("recommendedAccommodationId")
		if !found {
			log.Println("Recommended Accommodation ID not found in result")
			continue
		}
		recommendedAccommodations = append(recommendedAccommodations, accommodationID.(string))
	}

	if err := result.Err(); err != nil {
		return nil, err
	}

	return recommendedAccommodations, nil
}

func (store *RecommendationNeo4JStore) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	ctx, span := store.tracer.Start(ctx, "RecommendationNeo4JStore.GetUserByUsername")
	defer span.End()

	log.Println("RecommendationNeo4JStore.GetUserByUsername : GetUserByUsername reached")

	session := store.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: DATABASE})
	defer session.Close(ctx)

	requests, err := session.ExecuteRead(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		result, err := transaction.Run(ctx,
			"MATCH (u:User) "+
				"WHERE u.username = $username "+
				"RETURN u.id as id, u.username as username, u.userType as userType",
			map[string]any{"username": username})
		if err != nil {
			log.Printf("RecommendationNeo4JStore.GetUserByUsername.Run() : %s", err)
			return nil, err
		}

		var request *domain.User
		if result.Next(ctx) {
			record := result.Record()
			id, _ := record.Get("id")
			username, _ := record.Get("username")
			userType, _ := record.Get("userType")

			userTypeStr, ok := userType.(string)
			if !ok {
				return nil, fmt.Errorf("userType conversion error")
			}

			request = &domain.User{
				ID:       id.(string),
				Username: username.(string),
				UserType: domain.UserType(userTypeStr),
			}
		} else {
			return nil, fmt.Errorf(errors.ErrorRequestNotExists)
		}
		return request, nil
	})
	if err != nil {
		log.Printf("RecommendationNeo4JStore.GetUserByUsername.ExecuteRead() : %s", err)
		return nil, err
	}
	log.Println("RecommendationNeo4JStore.GetUserByUsername : GetUserByUsername successful")

	return requests.(*domain.User), nil
}

func (store *RecommendationNeo4JStore) GetUserByIdUsername(ctx context.Context, id string) (*domain.User, error) {
	ctx, span := store.tracer.Start(ctx, "RecommendationNeo4JStore.GetUserByUsername")
	defer span.End()

	log.Println("RecommendationNeo4JStore.GetUserByUsername : GetUserByUsername reached")

	session := store.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: DATABASE})
	defer session.Close(ctx)

	requests, err := session.ExecuteRead(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		result, err := transaction.Run(ctx,
			"MATCH (u:User) "+
				"WHERE u.id = $id "+
				"RETURN u.id as id, u.username as username, u.userType as userType",
			map[string]any{"id": id})
		if err != nil {
			log.Printf("RecommendationNeo4JStore.GetUserByUsername.Run() : %s", err)
			return nil, err
		}

		var request *domain.User
		if result.Next(ctx) {
			record := result.Record()
			id, _ := record.Get("id")
			username, _ := record.Get("username")
			userType, _ := record.Get("userType")

			userTypeStr, ok := userType.(string)
			if !ok {
				return nil, fmt.Errorf("userType conversion error")
			}

			request = &domain.User{
				ID:       id.(string),
				Username: username.(string),
				UserType: domain.UserType(userTypeStr),
			}
		} else {
			return nil, fmt.Errorf(errors.ErrorRequestNotExists)
		}
		return request, nil
	})
	if err != nil {
		log.Printf("RecommendationNeo4JStore.GetUserByUsername.ExecuteRead() : %s", err)
		return nil, err
	}
	log.Println("RecommendationNeo4JStore.GetUserByUsername : GetUserByUsername successful")

	return requests.(*domain.User), nil
}

func (store *RecommendationNeo4JStore) CreateUser(ctx context.Context, user *domain.User) error {
	ctx, span := store.tracer.Start(ctx, "RecommendationStore.SaveUser")
	defer span.End()

	log.Println("RecommendationStore.SaveUser : SaveUser reached")

	session := store.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: DATABASE})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx,
		func(transaction neo4j.ManagedTransaction) (any, error) {
			result, err := transaction.Run(ctx,
				"CREATE (u:User) SET u.id = $id, u.username = $username, "+
					"u.userType = $userType RETURN u.id + ', from node ' + id(u)",
				map[string]any{"id": user.ID, "username": user.Username, "userType": user.UserType})
			if err != nil {
				log.Printf("RecommendationStore.SaveUser.Run() : %s", err)
				return nil, err
			}

			if result.Next(ctx) {
				return result.Record().Values[0], nil
			}

			return nil, result.Err()
		})
	if err != nil {
		log.Printf("RecommendationStore.SaveUser.ExecuteWrite() : %s\n", err)
		return err
	}

	log.Println("RecommendationStore.SaveUser : SaveUser successful")

	return nil
}

func (store *RecommendationNeo4JStore) DeleteUser(ctx context.Context, id *string) error {
	ctx, span := store.tracer.Start(ctx, "RecommendationStore.DeleteUser")
	defer span.End()

	log.Printf("RecommendationStore.DeleteUser : DeleteUser reached")

	session := store.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: DATABASE})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		_, err := transaction.Run(ctx,
			"MATCH (u:User) "+
				"WHERE u.id = $id "+
				"DELETE u",
			map[string]any{"id": id})
		if err != nil {
			log.Printf("RecommendationStore.DeleteUser.Run() : %s", err)
			return nil, err
		}

		return nil, nil
	})

	if err != nil {
		log.Printf("RecommendationStore.DeleteUser.ExecuteWrite() : %s", err)

		return err
	}

	log.Printf("RecommendationStore.DeleteUser : DeleteUser successful")

	return nil
}

func (store *RecommendationNeo4JStore) UpdateUserUsername(ctx context.Context, user *domain.User) (*domain.User, error) {
	ctx, span := store.tracer.Start(ctx, "RecommendationStore.UpdateUserUsername")
	defer span.End()

	log.Printf("RecommendationStore.UpdateUserUsername : UpdateUserUsername reached")

	session := store.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: DATABASE})
	defer session.Close(ctx)

	request, err := session.ExecuteWrite(ctx,
		func(transaction neo4j.ManagedTransaction) (any, error) {
			result, err := transaction.Run(ctx,
				"MATCH (user:User) "+
					"WHERE user.id = $id "+
					"SET user.username = $username "+
					"RETURN user.id as id, user.username as username",
				map[string]any{"id": user.ID, "username": user.Username})
			if err != nil {
				log.Printf("RecommendationStore.UpdateUserUsername.Run() : %s", err)
				log.Printf("Error in creating request node and relationships because of: %s", err.Error())
				return nil, err
			}

			var request *domain.User
			if result.Next(ctx) {
				record := result.Record()
				id, _ := record.Get("id")
				username, _ := record.Get("username")
				request = &domain.User{
					ID:       id.(string),
					Username: username.(string),
				}
			}

			return request, nil
		})
	if err != nil {
		log.Printf("RecommendationStore.UpdateUserUsername.ExecuteWrite() : %s", err)
		return nil, err
	}

	log.Printf("RecommendationStore.UpdateUserUsername : UpdateUserUsername successful")

	return request.(*domain.User), nil
}
