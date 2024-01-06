package cache

import (
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis"
	"log"
	"os"
	"time"
)

type ImageCache struct {
	cli    *redis.Client
	logger *log.Logger
}

// Construct Redis client
func New(logger *log.Logger) (*ImageCache, error) {
	redisHost := os.Getenv("IMAGE_CACHE_HOST")
	redisPort := os.Getenv("IMAGE_CACHE_PORT")
	redisAddress := fmt.Sprintf("%s:%s", redisHost, redisPort)

	client := redis.NewClient(&redis.Options{
		Addr: redisAddress,
	})

	return &ImageCache{
		cli:    client,
		logger: logger,
	}, nil
}

// Check connection function
func (pc *ImageCache) Ping() {
	val, _ := pc.cli.Ping().Result()
	pc.logger.Println(val)
}

// Set key-value pair with default expiration
func (pc *ImageCache) Post(accommodationId string, imageName string, image []byte) error {

	err := pc.cli.Set(constructKey(accommodationId, imageName), image, 30*time.Minute).Err()
	if err == nil {
		pc.logger.Println("Cache hit - set image")
	}
	return err
}

// Get value by key
func (pc *ImageCache) Get(accommodationId string, imageName string) ([]byte, error) {
	value, err := pc.cli.Get(constructKey(accommodationId, imageName)).Bytes()
	if err != nil {
		return nil, err
	}

	pc.logger.Println("Cache hit - get image")
	return value, nil
}

func (pc *ImageCache) PostUrls(accommodationId string, urls []string) error {

	jsonValue, err := json.Marshal(urls)
	if err != nil {
		return err
	}

	err = pc.cli.Set(constructKeyUrls(accommodationId), jsonValue, 30*time.Minute).Err()
	if err != nil {
		return err
	}

	pc.logger.Println("Cache hit - set image url")
	return nil
}

func (pc *ImageCache) GetUrls(accommodationId string) ([]string, error) {

	jsonValue, err := pc.cli.Get(constructKeyUrls(accommodationId)).Result()
	if err != nil {
		return nil, err
	}

	var urls []string
	err = json.Unmarshal([]byte(jsonValue), &urls)
	if err != nil {
		return nil, err
	}

	pc.logger.Println("Cache hit - get image url")
	return urls, nil
}

// Check if given key exists
func (pc *ImageCache) Exists(accommodationId string, imageName string) bool {
	cnt, err := pc.cli.Exists(constructKey(accommodationId, imageName)).Result()
	if cnt == 1 {
		return true
	}
	if err != nil {
		return false
	}
	return false
}
