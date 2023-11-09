package application

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
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
