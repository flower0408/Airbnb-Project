package application

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cristalhq/jwt/v4"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"log"
	"net/http"
	"os"
	"recommendations_service/domain"
	"recommendations_service/errors"
)

type RecommendationService struct {
	store  domain.RecommendationStore
	tracer trace.Tracer
}

func NewRecommendationService(store domain.RecommendationStore, tracer trace.Tracer) *RecommendationService {
	return &RecommendationService{
		store:  store,
		tracer: tracer,
	}
}

func (service *RecommendationService) ExtractUsernameFromToken(tokenString string) (string, error) {
	verifier, _ := jwt.NewVerifierHS(jwt.HS256, []byte(os.Getenv("SECRET_KEY")))

	token, err := jwt.Parse([]byte(tokenString), verifier)
	if err != nil {
		return "", fmt.Errorf("Error parsing token: %s", err)
	}

	claims := token.Claims

	rawMessage := claims()

	byteSlice := []byte(rawMessage)

	var mapa map[string]interface{}
	err = json.Unmarshal(byteSlice, &mapa)
	if err != nil {
		fmt.Println("Greška prilikom dekodiranja JSON-a:", err)
		return "", fmt.Errorf("Error decoding token")
	}

	username, ok := mapa["username"].(string)
	if !ok {
		return "", fmt.Errorf("Username not found in token claims")
	}

	return username, nil
}

func (service *RecommendationService) GetRecommendAccommodationsId(ctx context.Context, id string) ([]string, error) {
	ctx, span := service.tracer.Start(ctx, "RecommendationService.GetRecommendAccommodationsId")
	defer span.End()

	return service.store.GetRecommendAccommodationsId(ctx, id)
}

func (service *RecommendationService) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	ctx, span := service.tracer.Start(ctx, "RecommendationService.GetUserByUsername")
	defer span.End()

	return service.store.GetUserByUsername(ctx, username)
}

func (service *RecommendationService) CreateUser(ctx context.Context, user *domain.User) error {
	ctx, span := service.tracer.Start(ctx, "RecommendationService.CreateUser")
	defer span.End()

	log.Println("RecommendationService.CreateUser : CreateUser reached")

	return service.store.CreateUser(ctx, user)
}

func (service *RecommendationService) DeleteUser(ctx context.Context, id *string) error {
	ctx, span := service.tracer.Start(ctx, "RecommendationService.DeleteUser")
	defer span.End()

	log.Println("RecommendationService.DeleteUser : DeleteUser reached")

	return service.store.DeleteUser(ctx, id)
}

func (service *RecommendationService) CreateAccommodation(ctx context.Context, accommodation *domain.Accommodation) error {
	ctx, span := service.tracer.Start(ctx, "RecommendationService.CreateAccommodation")
	defer span.End()

	log.Println("RecommendationService.CreateAccommodation : CreateAccommodation reached")

	return service.store.CreateAccommodation(ctx, accommodation)
}

func (service *RecommendationService) DeleteAccommodation(ctx context.Context, id *string) error {
	ctx, span := service.tracer.Start(ctx, "RecommendationService.DeleteAccommodation")
	defer span.End()

	log.Println("RecommendationService.DeleteAccommodation : DeleteAccommodation reached")

	return service.store.DeleteAccommodation(ctx, id)
}

func (service *RecommendationService) CreateRate(ctx context.Context, rate *domain.Rate) error {
	ctx, span := service.tracer.Start(ctx, "CreateRate.CreateRate")
	defer span.End()

	log.Println("RecommendationService.CreateRate : CreateRate reached")

	return service.store.CreateRate(ctx, rate)
}

func (service *RecommendationService) DeleteRate(ctx context.Context, id *string) error {
	ctx, span := service.tracer.Start(ctx, "RecommendationService.DeleteRate")
	defer span.End()

	log.Println("RecommendationService.DeleteRate : DeleteRate reached")

	return service.store.DeleteRate(ctx, id)
}

func (service *RecommendationService) UpdateRate(ctx context.Context, rate *domain.Rate) error {
	ctx, span := service.tracer.Start(ctx, "FollowService.UpdateRate")
	defer span.End()

	log.Println("RecommendationService.UpdateRate : UpdateRate reached")

	_, err := service.store.UpdateRate(ctx, rate)
	if err != nil {
		log.Printf("RecommendationService.UpdateRate.UpdateRate() : %s", err)
		return fmt.Errorf(errors.ErrorInAcceptRequest)
	}

	log.Println("RecommendationService.UpdateRate : UpdateRate successful")

	return nil
}

func (service *RecommendationService) CreateReservation(ctx context.Context, reservation *domain.Reservation) error {
	ctx, span := service.tracer.Start(ctx, "CreateRate.CreateReservation")
	defer span.End()

	log.Println("RecommendationService.CreateReservation : CreateReservation reached")

	return service.store.CreateReservation(ctx, reservation)
}

func (service *RecommendationService) ChangeUsername(ctx context.Context, username domain.UsernameChange) (string, int, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.ChangeUsername")
	defer span.End()

	currentUsername := username.OldUsername

	user, err := service.store.GetUserByUsername(ctx, currentUsername)
	if err != nil {
		log.Println(err)
		span.SetStatus(codes.Error, "Get user error")
		return "GetUserErr", http.StatusInternalServerError, err
	}

	user.Username = username.NewUsername

	_, err = service.store.UpdateUserUsername(ctx, user)
	if err != nil {
		span.SetStatus(codes.Error, "Internal server error")
		return "baseErr", http.StatusInternalServerError, err
	}

	fmt.Println("Username Updated Successfully")

	return "OK", http.StatusOK, nil
}
