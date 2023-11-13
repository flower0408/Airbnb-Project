package application

import (
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
	"user_service/domain"
)

type UserService struct {
	store domain.UserStore
}

func NewUserService(store domain.UserStore) *UserService {
	return &UserService{
		store: store,
	}
}

func (service *UserService) Get(id primitive.ObjectID) (*domain.User, error) {
	return service.store.Get(id)
}

func (service *UserService) GetAll() ([]*domain.User, error) {
	return service.store.GetAll()
}

func (service *UserService) GetOneUser(username string) (*domain.User, error) {
	retUser, err := service.store.GetOneUser(username)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("User not found")
	}
	return retUser, nil
}

func (service *UserService) DoesEmailExist(email string) (string, error) {
	user, err := service.store.GetByEmail(email)
	if err != nil {
		return "", err
	}

	return user.ID.Hex(), nil
}

func (service *UserService) Register(user *domain.User) (*domain.User, error) {

	userInfo := domain.User{
		ID:        user.ID,
		UserType:  user.UserType,
		Firstname: user.Firstname,
		Lastname:  user.Lastname,
		Gender:    user.Gender,
		Age:       user.Age,
		Residence: user.Residence,
		Email:     user.Email,
	}

	return service.store.Register(&userInfo)

}
