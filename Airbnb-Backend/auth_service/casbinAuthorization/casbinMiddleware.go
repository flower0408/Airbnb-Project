package casbinAuthorization

import (
	"errors"
	"github.com/casbin/casbin"
	"github.com/cristalhq/jwt/v4"
	"github.com/sirupsen/logrus"
	"log"
	"net/http"
	"os"
	"strings"
)

var jwtKey = []byte(os.Getenv("SECRET_KEY"))

var verifier, _ = jwt.NewVerifierHS(jwt.HS256, jwtKey)

func parseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse([]byte(tokenString), verifier)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return token, nil
}

func extractUserType(r *http.Request) (string, error) {
	bearer := r.Header.Get("Authorization")
	if bearer == "" {
		return "Unauthenticated", nil
	}

	bearerToken := strings.Split(bearer, "Bearer ")
	if len(bearerToken) != 2 {
		return "", errors.New("invalid token format")
	}

	tokenString := bearerToken[1]
	token, err := parseToken(tokenString)
	if err != nil {
		return "", err
	}

	claims := extractClaims(token)
	return claims["userType"], nil
}

func extractClaims(token *jwt.Token) map[string]string {
	var claims map[string]string

	err := jwt.ParseClaims(token.Bytes(), verifier, &claims)
	if err != nil {
		log.Println(err)
	}

	return claims
}

func CasbinMiddleware(e *casbin.Enforcer, logger *logrus.Logger) func(http.Handler) http.Handler {
	e.EnableLog(true)
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			userRole, err := extractUserType(r)
			if err != nil {
				logger.Error("Unauthorized access attempt")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			res, err := e.EnforceSafe(userRole, r.URL.Path, r.Method)
			if err != nil {
				log.Println("enforce error:", err)
				logger.Error("Error enforcing authorization policy")
				http.Error(w, "unauthorized user", http.StatusUnauthorized)
				return
			}

			if res {
				log.Println("redirect")
				next.ServeHTTP(w, r)
			} else {
				logger.Warn("Unauthorized access attempt: forbidden")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}

		return http.HandlerFunc(fn)
	}
}
