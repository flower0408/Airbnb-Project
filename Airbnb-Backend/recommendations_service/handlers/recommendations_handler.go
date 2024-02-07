package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/casbin/casbin"
	"github.com/cristalhq/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"log"
	"net/http"
	"os"
	"recommendations_service/casbinAuthorization"
	"recommendations_service/domain"
	"recommendations_service/errors"
	"recommendations_service/service"
	"strings"
)

var (
	jwtKey      = []byte(os.Getenv("SECRET_KEY"))
	verifier, _ = jwt.NewVerifierHS(jwt.HS256, jwtKey)
)

type RecommendationHandler struct {
	service *application.RecommendationService
	tracer  trace.Tracer
	logger  *logrus.Logger
}

func NewRecommendationHandler(service *application.RecommendationService, tracer trace.Tracer, logger *logrus.Logger) *RecommendationHandler {
	return &RecommendationHandler{
		service: service,
		tracer:  tracer,
		logger:  logger,
	}
}

func (handler *RecommendationHandler) Init(router *mux.Router) {

	CasbinMiddleware1, err := casbin.NewEnforcerSafe("./rbac_model.conf", "./policy.csv")

	log.Println("user service successful init of enforcer")
	if err != nil {
		log.Fatal(err)
	}

	router.Use(ExtractTraceInfoMiddleware)
	router.HandleFunc("/createUser", handler.CreateUser).Methods("POST")
	router.HandleFunc("/deleteUser/{id}", handler.DeleteUser).Methods("DELETE")
	router.HandleFunc("/changeUsername", handler.ChangeUsername).Methods("POST")
	router.HandleFunc("/createAccommodation", handler.CreateAccommodation).Methods("POST")
	router.HandleFunc("/deleteAccommodation/{id}", handler.DeleteAccommodation).Methods("DELETE")
	router.HandleFunc("/createRate", handler.CreateRate).Methods("POST")
	router.HandleFunc("/deleteRate/{id}", handler.DeleteRate).Methods("DELETE")
	router.HandleFunc("/createReservation", handler.CreateReservation).Methods("POST")
	router.HandleFunc("/updateRate/{id}", handler.UpdateRate).Methods("PATCH")
	router.HandleFunc("/updateRate", handler.UpdateRate).Methods("PATCH")
	router.HandleFunc("/recommended", handler.GetRecommendAccommodationsId).Methods("GET")

	http.Handle("/", router)
	log.Fatal(http.ListenAndServeTLS(":8006", "recommendations_service-cert.pem", "recommendations_service-key.pem", casbinAuthorization.CasbinMiddleware(CasbinMiddleware1, handler.logger)(router)))
}

type ValidationError struct {
	Message string `json:"message"`
}

func extractTokenFromHeader(request *http.Request) (string, error) {
	authHeader := request.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("No Authorization header found")
	}

	// Check if the header starts with "Bearer "
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("Invalid Authorization header format")
	}

	// Extract the token
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	return tokenString, nil
}

func (handler *RecommendationHandler) GetRecommendAccommodationsId(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "RecommendationHandler.GetRecommendAccommodationsId")
	defer span.End()

	handler.logger.Infoln("RecommendationHandler.GetRecommendAccommodationsId : GetRecommendAccommodationsId endpoint reached")

	log.Println("RecommendationHandler.GetRecommendAccommodationsId: GetRecommendAccommodationsId reached") // Extract username from request
	tokenString, err := extractTokenFromHeader(req)
	if err != nil {
		handler.logger.Errorf("UserHandler.GetRecommendAccommodationsId : No token found")
		span.SetStatus(codes.Error, "No token found")
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("No token found"))
		return
	}

	username, err := handler.service.ExtractUsernameFromToken(tokenString)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.GetRecommendAccommodationsId : Error parsing token")
		fmt.Println("Error extracting username:", err)
		span.SetStatus(codes.Error, "Error parsing token")
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Error parsing token"))
		return
	}

	user, err := handler.service.GetUserByUsername(ctx, username)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.GetRecommendAccommodationsId : Internal server error")
		log.Printf("RecommendationHandler.GetRecommendAccommodationsId: GetUserByUsername error: %s", err)
		writer.WriteHeader(http.StatusInternalServerError)
		writer.Write([]byte("Internal server error"))
		return
	}

	recommendations, err := handler.service.GetRecommendAccommodationsId(ctx, user.ID)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.GetRecommendAccommodationsId : Internal server error")
		log.Printf("RecommendationHandler.GetRecommendAccommodationsId: %s", err)
		writer.WriteHeader(http.StatusInternalServerError)
		writer.Write([]byte("Internal server error"))
		return
	}

	response := map[string]interface{}{
		"recommendations": recommendations,
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.GetRecommendAccommodationsId : Internal server error")
		log.Printf("Error encoding JSON response: %s", err)
		writer.WriteHeader(http.StatusInternalServerError)
		writer.Write([]byte("Internal server error"))
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	writer.Write(jsonResponse)

	handler.logger.Infoln("RecommendationHandler.GetRecommendAccommodationsId : GetRecommendAccommodationsId success")
	log.Println("RecommendationHandler.GetRecommendAccommodationsId: GetRecommendAccommodationsId successful")
}

func (handler *RecommendationHandler) ChangeUsername(writer http.ResponseWriter, request *http.Request) {
	ctx, span := handler.tracer.Start(request.Context(), "UserHandler.ChangeUsername")
	defer span.End()

	handler.logger.Infoln("RecommendationHandler.ChangeUsername : ChangeUsername endpoint reached")

	var username domain.UsernameChange
	err := json.NewDecoder(request.Body).Decode(&username)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.ChangeUsername : Status bad request")
		log.Println(err)
		span.SetStatus(codes.Error, "Status bad request")
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	status, statusCode, err := handler.service.ChangeUsername(ctx, username)

	if err != nil {
		handler.logger.Errorf("RecommendationHandler.ChangeUsername : Error in ChangeUsername")
		span.SetStatus(codes.Error, err.Error())
		log.Println("Error in ChangeUsername:", err)
		var errorMessage string

		switch status {
		case "GetUserErr":
			errorMessage = "Error getting user"
		case "baseErr":
			errorMessage = "Internal server error"
		default:
			errorMessage = "An error occurred: " + err.Error()
		}

		span.SetStatus(codes.Error, "Error")
		http.Error(writer, errorMessage, statusCode)
		return
	}
	handler.logger.Infoln("RecommendationHandler.ChangeUsername : ChangeUsername success")
	writer.WriteHeader(http.StatusOK)
}

func (handler *RecommendationHandler) DeleteUser(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "RecommendationHandler.DeleteUser")
	defer span.End()

	handler.logger.Infoln("RecommendationHandler.DeleteUser : DeleteUser endpoint reached")
	log.Println("RecommendationHandler.DeleteUser : DeleteUser reached")

	vars := mux.Vars(req)
	userId, ok := vars["id"]
	if !ok {
		handler.logger.Errorf("RecommendationHandler.DeleteUser : Error status bad request")
		log.Println("RecommendationHandler.DeleteUser.Vars() : bad request")
		http.Error(writer, errors.BadRequestError, http.StatusBadRequest)
	}

	err := handler.service.DeleteUser(ctx, &userId)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.DeleteUser : Status bad request")
		log.Println("RecommendationHandler.DeleteUser.DeclineRequest() : %s", err)
		http.Error(writer, errors.BadRequestError, http.StatusBadRequest)
	}

	log.Println("RecommendationHandler.DeleteUser : DeleteUser successful")
	handler.logger.Infoln("RecommendationHandler.DeleteUser : DeleteUser success")
	writer.WriteHeader(http.StatusOK)
}

func (handler *RecommendationHandler) CreateUser(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "RecommendationHandler.CreateUser")
	defer span.End()

	handler.logger.Infoln("RecommendationHandler.CreateUser : CreateUser endpoint reached")
	log.Printf("RecommendationHandler.CreateUser : CreateUser reached")

	var request domain.User
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.CreateUser : Error status bad request")
		log.Printf("RecommendationHandler.CreateUser.Decode() : %s", err)
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}

	err = handler.service.CreateUser(ctx, &request)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.CreateUser : Error status bad request")
		log.Printf("RecommendationHandler.CreateUser.CreateUser() : %s", err)
		http.Error(writer, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("RecommendationHandler.CreateUser : CreateUser successful")
	handler.logger.Infoln("RecommendationHandler.CreateUser : CreateUser success")
	writer.WriteHeader(http.StatusOK)
}

func (handler *RecommendationHandler) CreateAccommodation(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "RecommendationHandler.CreateAccommodation")
	defer span.End()

	handler.logger.Infoln("RecommendationHandler.CreateAccommodation : CreateAccommodation endpoint reached")
	log.Printf("RecommendationHandler.CreateAccommodation : CreateAccommodation reached")

	var request domain.Accommodation
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.CreateAccommodation : Error status bad request")
		log.Printf("RecommendationHandler.CreateAccommodation.Decode() : %s", err)
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}

	err = handler.service.CreateAccommodation(ctx, &request)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.CreateAccommodation : Error internal server error")
		log.Printf("RecommendationHandler.CreateAccommodation.CreateAccommodation() : %s", err)
		http.Error(writer, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("RecommendationHandler.CreateAccommodation : CreateAccommodation successful")
	handler.logger.Infoln("RecommendationHandler.CreateAccommodation : CreateAccommodation success")
	writer.WriteHeader(http.StatusOK)
}

func (handler *RecommendationHandler) DeleteAccommodation(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "RecommendationHandler.DeleteAccommodation")
	defer span.End()

	handler.logger.Infoln("RecommendationHandler.DeleteAccommodation : DeleteAccommodation endpoint reached")
	log.Println("RecommendationHandler.DeleteAccommodation : DeleteAccommodation reached")

	vars := mux.Vars(req)
	accommodationId, ok := vars["id"]
	if !ok {
		handler.logger.Errorf("RecommendationHandler.DeleteAccommodation : Error bad request")
		log.Println("RecommendationHandler.DeleteAccommodation.Vars() : bad request")
		http.Error(writer, errors.BadRequestError, http.StatusBadRequest)
	}

	err := handler.service.DeleteAccommodation(ctx, &accommodationId)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.DeleteAccommodation : Error bad request")
		log.Println("RecommendationHandler.DeleteAccommodation.DeclineRequest() : %s", err)
		http.Error(writer, errors.BadRequestError, http.StatusBadRequest)
	}

	log.Println("RecommendationHandler.DeleteAccommodation : DeleteAccommodation successful")
	handler.logger.Infoln("RecommendationHandler.DeleteAccommodation : DeleteAccommodation success")
	writer.WriteHeader(http.StatusOK)
}

func (handler *RecommendationHandler) CreateRate(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "RecommendationHandler.CreateRate")
	defer span.End()

	handler.logger.Infoln("RecommendationHandler.CreateRate : CreateRate endpoint reached")
	log.Printf("RecommendationHandler.CreateRate : CreateRate reached")

	var request domain.Rate
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.CreateRate : Error bad request")
		log.Printf("RecommendationHandler.CreateRate.Decode() : %s", err)
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}

	err = handler.service.CreateRate(ctx, &request)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.CreateRate : Error internal server error")
		log.Printf("RecommendationHandler.CreateRate.CreateRate() : %s", err)
		http.Error(writer, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("RecommendationHandler.CreateRate : CreateRate successful")
	handler.logger.Infoln("RecommendationHandler.CreateRate : CreateRate success")
	writer.WriteHeader(http.StatusOK)
}

func (handler *RecommendationHandler) DeleteRate(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "RecommendationHandler.DeleteRate")
	defer span.End()

	handler.logger.Infoln("RecommendationHandler.DeleteRate : DeleteRate endpoint reached")
	log.Println("RecommendationHandler.DeleteRate : DeleteRate reached")

	vars := mux.Vars(req)
	rateId, ok := vars["id"]
	if !ok {
		handler.logger.Errorf("RecommendationHandler.DeleteRate : Error bad request")
		log.Println("RecommendationHandler.DeleteRate.Vars() : bad request")
		http.Error(writer, errors.BadRequestError, http.StatusBadRequest)
	}

	err := handler.service.DeleteRate(ctx, &rateId)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.DeleteRate : Error bad request")
		log.Println("RecommendationHandler.DeleteRate.DeclineRequest() : %s", err)
		http.Error(writer, errors.BadRequestError, http.StatusBadRequest)
	}

	log.Println("RecommendationHandler.DeleteRate : DeleteRate successful")
	handler.logger.Infoln("RecommendationHandler.DeleteRate : DeleteRate success")
	writer.WriteHeader(http.StatusOK)
}

func (handler *RecommendationHandler) UpdateRate(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "FollowHandler.AcceptRequest")
	defer span.End()

	handler.logger.Infoln("RecommendationHandler.UpdateRate : UpdateRate endpoint reached")
	log.Println("RecommendationHandler.UpdateRate : UpdateRate reached")

	var rate domain.Rate
	err := json.NewDecoder(req.Body).Decode(&rate)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.UpdateRate : Error bad request")
		log.Printf("RecommendationHandler.UpdateRate.Decode() : %s\n", err)
		http.Error(writer, errors.BadRequestError, http.StatusBadRequest)
		return
	}

	err = handler.service.UpdateRate(ctx, &rate)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.UpdateRate : Error bad request")
		log.Printf("RecommendationHandler.UpdateRate.AcceptRequest() : %s\n", err)
		http.Error(writer, errors.BadRequestError, http.StatusBadRequest)
		return
	}

	log.Println("RecommendationHandler.UpdateRate : UpdateRate successful")
	handler.logger.Infoln("RecommendationHandler.UpdateRate : UpdateRate success")
	writer.WriteHeader(http.StatusOK)
}

func (handler *RecommendationHandler) CreateReservation(writer http.ResponseWriter, req *http.Request) {
	ctx, span := handler.tracer.Start(req.Context(), "RecommendationHandler.CreateReservation")
	defer span.End()

	handler.logger.Infoln("RecommendationHandler.CreateReservation : CreateReservation endpoint reached")
	log.Printf("RecommendationHandler.CreateReservation : CreateReservation reached")

	var request domain.Reservation
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.CreateReservation : Error bad request")
		log.Printf("RecommendationHandler.CreateReservation.Decode() : %s", err)
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}

	err = handler.service.CreateReservation(ctx, &request)
	if err != nil {
		handler.logger.Errorf("RecommendationHandler.CreateReservation : Error internal server error")
		log.Printf("RecommendationHandler.CreateReservation.CreateRate() : %s", err)
		http.Error(writer, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("RecommendationHandler.CreateReservation : CreateReservation successful")
	handler.logger.Infoln("RecommendationHandler.CreateReservation : CreateReservation success")
	writer.WriteHeader(http.StatusOK)
}

func ExtractTraceInfoMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
