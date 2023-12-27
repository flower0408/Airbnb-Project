package application

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.opentelemetry.io/otel/trace"
	"log"
	"net/http"
	"user_service/domain"
)

type UserService struct {
	store  domain.UserStore
	tracer trace.Tracer
}

func NewUserService(store domain.UserStore, tracer trace.Tracer) *UserService {
	return &UserService{
		store:  store,
		tracer: tracer,
	}
}

func (service *UserService) Get(ctx context.Context, id primitive.ObjectID) (*domain.User, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.Get")
	defer span.End()

	return service.store.Get(ctx, id)
}

func (service *UserService) GetAll(ctx context.Context) ([]*domain.User, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.GetAll")
	defer span.End()

	return service.store.GetAll(ctx)
}

func (service *UserService) GetOneUser(ctx context.Context, username string) (*domain.User, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.GetOneUser")
	defer span.End()

	retUser, err := service.store.GetOneUser(ctx, username)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("User not found")
	}
	return retUser, nil
}

func (service *UserService) GetOneUserId(ctx context.Context, username string) (primitive.ObjectID, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.GetOneUserId")
	defer span.End()

	retUser, err := service.store.GetOneUser(ctx, username)
	if err != nil {
		log.Println(err)
		return primitive.NilObjectID, fmt.Errorf("User not found")
	}
	return retUser.ID, nil
}

func (service *UserService) DoesEmailExist(ctx context.Context, email string) (string, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.DoesMailExist")
	defer span.End()

	user, err := service.store.GetByEmail(ctx, email)
	if err != nil {
		return "", err
	}

	return user.ID.Hex(), nil
}

func (service *UserService) Register(ctx context.Context, user *domain.User) (*domain.User, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.Register")
	defer span.End()

	userInfo := domain.User{
		ID:        user.ID,
		UserType:  user.UserType,
		Firstname: user.Firstname,
		Lastname:  user.Lastname,
		Gender:    user.Gender,
		Age:       user.Age,
		Residence: user.Residence,
		Email:     user.Email,
		Username:  user.Username,
	}

	return service.store.Register(ctx, &userInfo)

}

func (service *UserService) UpdateUser(ctx context.Context, updateUser *domain.User) (*domain.User, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.UpdateUser")
	defer span.End()

	return service.store.UpdateUser(ctx, updateUser)
}

func (service *UserService) DeleteAccount(ctx context.Context, userID primitive.ObjectID) error {
	ctx, span := service.tracer.Start(ctx, "UserService.DeleteAccount")
	defer span.End()

	err := service.store.DeleteAccount(ctx, userID)
	if err != nil {
		return err
	}

	return nil
}

func (service *UserService) ChangeUsername(ctx context.Context, username domain.UsernameChange) (string, int, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.ChangeUsername")
	defer span.End()

	currentUsername := username.OldUsername

	user, err := service.store.GetOneUser(ctx, currentUsername)
	if err != nil {
		log.Println(err)
		return "GetUserErr", http.StatusInternalServerError, err
	}

	user.Username = username.NewUsername

	err = service.store.UpdateUserUsername(ctx, user)
	if err != nil {
		return "baseErr", http.StatusInternalServerError, err
	}

	fmt.Println("Username Updated Successfully")

	// Return the updated token
	return "OK", http.StatusOK, nil
}
