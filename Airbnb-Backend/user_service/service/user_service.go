package application

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"log"
	"net/http"
	"user_service/domain"
)

type UserService struct {
	store  domain.UserStore
	tracer trace.Tracer
	logger *logrus.Logger
}

func NewUserService(store domain.UserStore, tracer trace.Tracer, logger *logrus.Logger) *UserService {
	return &UserService{
		store:  store,
		tracer: tracer,
		logger: logger,
	}
}

func (service *UserService) Get(ctx context.Context, id primitive.ObjectID) (*domain.User, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.Get")
	defer span.End()

	service.logger.Infoln("UserService.Get : Get service reached")

	return service.store.Get(ctx, id)
}

func (service *UserService) GetAll(ctx context.Context) ([]*domain.User, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.GetAll")
	defer span.End()

	service.logger.Infoln("UserService.GetAll : GetAll service reached")

	return service.store.GetAll(ctx)
}

func (service *UserService) GetOneUser(ctx context.Context, username string) (*domain.User, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.GetOneUser")
	defer span.End()

	service.logger.Infoln("UserService.GetOneUser : GetOneUser service reached")

	retUser, err := service.store.GetOneUser(ctx, username)
	if err != nil {
		service.logger.Errorln("UserService.GetOneUser : User not found")
		span.SetStatus(codes.Error, "User not found")
		log.Println(err)
		return nil, fmt.Errorf("User not found")
	}
	return retUser, nil
}

func (service *UserService) GetOneUserId(ctx context.Context, username string) (primitive.ObjectID, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.GetOneUserId")
	defer span.End()

	service.logger.Infoln("UserService.GetOneUserId : GetOneUserId service reached")

	retUser, err := service.store.GetOneUser(ctx, username)
	if err != nil {
		log.Println(err)
		service.logger.Errorln("UserService.GetOneUserId : User not found")
		span.SetStatus(codes.Error, "User not found")
		return primitive.NilObjectID, fmt.Errorf("User not found")
	}
	return retUser.ID, nil
}

func (service *UserService) DoesEmailExist(ctx context.Context, email string) (string, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.DoesMailExist")
	defer span.End()

	service.logger.Infoln("UserService.DoesEmailExist : DoesEmailExist service reached")

	user, err := service.store.GetByEmail(ctx, email)
	if err != nil {
		service.logger.Errorln("UserService.DoesEmailExist : Error mail exist")
		span.SetStatus(codes.Error, "Error mail exist")
		return "", err
	}

	return user.ID.Hex(), nil
}

func (service *UserService) Register(ctx context.Context, user *domain.User) (*domain.User, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.Register")
	defer span.End()

	service.logger.Infoln("UserService.Register : Register service reached")

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

	service.logger.Infoln("UserService.Register : register service finished")
	return service.store.Register(ctx, &userInfo)

}

func (service *UserService) UpdateUser(ctx context.Context, updateUser *domain.User) (*domain.User, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.UpdateUser")
	defer span.End()

	service.logger.Infoln("UserService.UpdateUser : UpdateUser service reached")

	return service.store.UpdateUser(ctx, updateUser)
}

func (service *UserService) IsHighlighted(ctx context.Context, host string, authToken string) (bool, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.IsHighlighted")
	defer span.End()

	service.logger.Infoln("UserService.IsHighlighted : IsHighlighted service reached")

	return service.store.IsHighlighted(ctx, host, authToken)
}

func (service *UserService) DeleteAccount(ctx context.Context, userID primitive.ObjectID) error {
	ctx, span := service.tracer.Start(ctx, "UserService.DeleteAccount")
	defer span.End()

	service.logger.Infoln("UserService.DeleteAccount : DeleteAccount service reached")

	err := service.store.DeleteAccount(ctx, userID)
	if err != nil {
		service.logger.Errorln("UserService.DeleteAccount : Error deleting account")
		span.SetStatus(codes.Error, "Error deleting account")
		return err
	}

	service.logger.Infoln("UserService.DeleteAccount : DeleteAccount service finished")
	return nil
}

func (service *UserService) ChangeUsername(ctx context.Context, username domain.UsernameChange) (string, int, error) {
	ctx, span := service.tracer.Start(ctx, "UserService.ChangeUsername")
	defer span.End()

	service.logger.Infoln("UserService.ChangeUsername : ChangeUsername service reached")

	currentUsername := username.OldUsername

	user, err := service.store.GetOneUser(ctx, currentUsername)
	if err != nil {
		service.logger.Errorln("UserService.ChangeUsername : Get user error")
		log.Println(err)
		span.SetStatus(codes.Error, "Get user error")
		return "GetUserErr", http.StatusInternalServerError, err
	}

	user.Username = username.NewUsername

	err = service.store.UpdateUserUsername(ctx, user)
	if err != nil {
		service.logger.Errorln("UserService.ChangeUsername : Internal server error")
		span.SetStatus(codes.Error, "Internal server error")
		return "baseErr", http.StatusInternalServerError, err
	}

	fmt.Println("Username Updated Successfully")
	service.logger.Infoln("UserService.ChangeUsername : ChangeUsername service finished")
	return "OK", http.StatusOK, nil
}
