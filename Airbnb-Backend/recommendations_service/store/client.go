package store

import (
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"log"
	"net/http"
)

func GetClient(host, port, user, pass string, httpClient *http.Client) (*neo4j.DriverWithContext, error) {
	uri := fmt.Sprintf("bolt://%s:%s/", host, port)
	log.Printf("neo4j uri: %s", uri)
	log.Printf("USER: %s, PASS: %s", user, pass)
	auth := neo4j.BasicAuth(user, pass, "")

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	driver, err := neo4j.NewDriverWithContext(uri, auth)
	return &driver, err
}
