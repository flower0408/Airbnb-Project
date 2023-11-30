package casbinAuthorization

import (
	"errors"
	"github.com/casbin/casbin"
	"github.com/cristalhq/jwt/v4"
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

/*
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
*/
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
		log.Println("Error parsing token:", err)
		return "", err
	}

	claims := extractClaims(token)
	userType, ok := claims["userType"]
	if !ok {
		log.Println("userType claim not found in token")
		return "", errors.New("userType claim not found in token")
	}

	return userType, nil
}

func extractClaims(token *jwt.Token) map[string]string {
	var claims map[string]string

	err := jwt.ParseClaims(token.Bytes(), verifier, &claims)
	if err != nil {
		log.Println(err)
	}

	return claims
}

func CasbinMiddleware(e *casbin.Enforcer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			userRole, err := extractUserType(r)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			res, err := e.EnforceSafe(userRole, r.URL.Path, r.Method)
			if err != nil {
				log.Println("enforce error:", err)
				http.Error(w, "unauthorized user", http.StatusUnauthorized)
				return
			}

			if res {
				log.Println("redirect")
				next.ServeHTTP(w, r)
			} else {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}

		return http.HandlerFunc(fn)
	}
}
