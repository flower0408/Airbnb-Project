package store

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"net/http"
)

func GetClientWithHTTPConfig(host, port string, httpClient *http.Client) (*mongo.Client, error) {
	uri := fmt.Sprintf("mongodb://%s:%s/", host, port)
	optionsClient := options.Client().ApplyURI(uri).SetHTTPClient(httpClient)
	return mongo.Connect(context.TODO(), optionsClient)
}
