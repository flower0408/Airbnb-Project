package handlers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reservations_service/data"
	"strconv"
	"strings"
	"time"
)

type AppointmentHandler struct {
	logger          *logrus.Logger
	appointmentRepo *data.AppointmentRepo
	tracer          trace.Tracer
}

var (
	accommodationServiceHost = os.Getenv("ACCOMMODATIONS_SERVICE_HOST")
	accommodationServicePort = os.Getenv("ACCOMMODATIONS_SERVICE_PORT")
)

func NewAppointmentHandler(logger *logrus.Logger, r *data.AppointmentRepo, t trace.Tracer) *AppointmentHandler {
	return &AppointmentHandler{logger, r, t}
}

// mongo
func (r *AppointmentHandler) CreateAppointment(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.CreateAppointment")
	defer span.End()

	r.logger.Infoln("AppointmentHandler.CreateAppointment : CreateAppointment endpoint reached")

	appointment := h.Context().Value(KeyProduct{}).(*data.Appointment)
	err := r.appointmentRepo.InsertAppointment(ctx, appointment)
	if err != nil {
		span.SetStatus(codes.Error, "Error creating appointment")
		if err.Error() == "Error adding appointment. Date already exists. " {
			r.logger.Errorf("AppointmentHandler.CreateAppointment : Error adding appointment. Date already exists. ")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error adding appointment. Date already exists. "))
		} else if err.Error() == "Error adding appointment. Cannot add appointment in the past." {
			r.logger.Errorf("AppointmentHandler.CreateAppointment : Error adding appointment. Cannot add appointment in the past.")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error adding appointment. Cannot add appointment in the past."))
		} else {
			r.logger.Errorf("AppointmentHandler.CreateAppointment : Database exception: %s", err)
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error creating reservation."))
		}
		return
	}

	r.logger.Infoln("AppointmentHandler.CreateAppointment : CreateAppointment finished")
	rw.WriteHeader(http.StatusOK)
}

func (r *AppointmentHandler) GetAllAppointment(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.GetAllAppointment")
	defer span.End()

	r.logger.Infoln("AppointmentHandler.GetAllAppointment : GetAllAppointment endpoint reached")

	appointments, err := r.appointmentRepo.GetAllAppointment(ctx)
	if err != nil {
		r.logger.Errorf("AppointmentHandler.GetAllAppointment : Database exception")
		span.SetStatus(codes.Error, "Database exception")
	}

	if appointments == nil {
		return
	}

	err = appointments.ToJSON(rw)
	if err != nil {
		r.logger.Errorf("AppointmentHandler.GetAllAppointment : Unable to convert to json")
		span.SetStatus(codes.Error, "Unable to convert to json")
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		return
	}
}

func (r *AppointmentHandler) GetAppointmentsByAccommodation(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.GetAppointmentsByAccommodation")
	defer span.End()

	r.logger.Infoln("AppointmentHandler.GetAppointmentsByAccommodation : GetAppointmentsByAccommodation endpoint reached")

	vars := mux.Vars(h)
	id := vars["id"]

	appointments, err := r.appointmentRepo.GetAppointmentsByAccommodation(ctx, id)
	if err != nil {
		r.logger.Errorf("AppointmentHandler.GetAppointmentsByAccommodation : Database exception")
		span.SetStatus(codes.Error, "Database exception")
		r.logger.Print("Database exception")
		http.Error(rw, "Database exception", http.StatusInternalServerError)
		return
	}

	if appointments == nil {
		return
	}

	err = appointments.ToJSON(rw)
	if err != nil {
		r.logger.Errorf("AppointmentHandler.GetAppointmentsByAccommodation : Unable to convert to json")
		span.SetStatus(codes.Error, "Unable to convert to json")
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		r.logger.Fatal("Unable to convert to json")
		return
	}
}

func (r *AppointmentHandler) GetAppointmentsByDate(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.GetAppointmentsByDate")
	defer span.End()

	r.logger.Infoln("AppointmentHandler.GetAppointmentsByDate : GetAppointmentsByDate endpoint reached")

	startDateStr := h.URL.Query().Get("startDate")
	endDateStr := h.URL.Query().Get("endDate")

	startDate, err := time.Parse(time.RFC3339, startDateStr)
	if err != nil {
		r.logger.Errorf("AppointmentHandler.GetAppointmentsByDate : Invalid startDate parameter")
		span.SetStatus(codes.Error, "Invalid startDate parameter")
		http.Error(rw, "Invalid startDate parameter", http.StatusBadRequest)
		return
	}

	endDate, err := time.Parse(time.RFC3339, endDateStr)
	if err != nil {
		r.logger.Errorf("AppointmentHandler.GetAppointmentsByDate : Invalid endDate parameter")
		span.SetStatus(codes.Error, "Invalid endDate parameter")
		http.Error(rw, "Invalid endDate parameter", http.StatusBadRequest)
		return
	}

	appointments, err := r.appointmentRepo.GetAppointmentsByDate(ctx, startDate, endDate)
	if err != nil {
		r.logger.Errorf("AppointmentHandler.GetAppointmentsByDate : Unable to retrieve appointments")
		span.SetStatus(codes.Error, "Unable to retrieve appointments")
		http.Error(rw, "Unable to retrieve appointments", http.StatusInternalServerError)
		return
	}

	if len(appointments) == 0 {
		return
	}

	accommodationIDs := make(map[string]struct{})
	for _, appointment := range appointments {
		accommodationIDs[appointment.AccommodationId] = struct{}{}
	}

	uniqueAccommodationIDs := make([]string, 0, len(accommodationIDs))
	for id := range accommodationIDs {
		uniqueAccommodationIDs = append(uniqueAccommodationIDs, id)
	}

	fmt.Printf("Unique Accommodation IDs: %+v\n", uniqueAccommodationIDs)

	err = appointments.ToJSON(rw)
	if err != nil {
		r.logger.Errorf("AppointmentHandler.GetAppointmentsByDate : Unable to convert to json")
		span.SetStatus(codes.Error, "Unable to convert to JSON")
		http.Error(rw, "Unable to convert to JSON", http.StatusInternalServerError)
		return
	}
}

func (r *AppointmentHandler) UpdateAppointment(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.UpdateAppointment")
	defer span.End()

	r.logger.Infoln("AppointmentHandler.UpdateAppointment : UpdateAppointment endpoint reached")

	vars := mux.Vars(h)
	id := vars["id"]

	appointment := h.Context().Value(KeyProduct{}).(*data.Appointment)

	tokenString, err := extractTokenFromHeader(h)
	if err != nil {
		r.logger.Errorf("AppointmentHandler.UpdateAppointment : Unable to convert to json")
		span.SetStatus(codes.Error, "No token found")
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("No token found"))
		return
	}

	err = r.appointmentRepo.UpdateAppointment(ctx, id, appointment, tokenString)
	if err != nil {
		span.SetStatus(codes.Error, "Error update appointment")
		if err.Error() == "Reservation exists for the appointment." {
			r.logger.Errorf("AppointmentHandler.UpdateAppointment : Reservation exists for the appointment. Update not allowed")
			rw.WriteHeader(http.StatusMethodNotAllowed)
			rw.Write([]byte("Reservation exists for the appointment. Update not allowed."))
		} else if err.Error() == "Error editing appointment. Date already exists. " {
			r.logger.Errorf("AppointmentHandler.UpdateAppointment : Error editing appointment. Date already exists")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error editing appointment. Date already exists. "))
		} else if err.Error() == "Error editing appointment. Cannot add appointment in the past." {
			r.logger.Errorf("AppointmentHandler.UpdateAppointment : Error editing appointment. Cannot add appointment in the past.")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error editing appointment. Cannot add appointment in the past."))
		} else {
			r.logger.Errorf("AppointmentHandler.UpdateAppointment : Error updating appointment")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error updating appointment."))
		}
		return
	}

	r.logger.Infoln("AppointmentHandler.UpdateAppointment : UpdateAppointment finished")
	span.SetStatus(codes.Ok, "")
	rw.WriteHeader(http.StatusOK)
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

func (r *AppointmentHandler) DeleteAppointmentsByAccommodationIDs(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.DeleteAppointmentsByAccommodationIDs")
	defer span.End()

	r.logger.Infoln("AppointmentHandler.DeleteAppointmentsByAccommodationIDs : DeleteAppointmentsByAccommodationIDs endpoint reached")

	vars := mux.Vars(h)
	userId := vars["id"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		r.logger.Errorf("AppointmentHandler.DeleteAppointmentsByAccommodationIDs : Error extracting Bearer token")
		span.SetStatus(codes.Error, "Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	accommodationEndpoint := fmt.Sprintf("https://%s:%s/owner/%s", accommodationServiceHost, accommodationServicePort, userId)
	accommodationResponse, err := r.HTTPSRequestWithouthBody(ctx, authToken, accommodationEndpoint, "GET")
	if err != nil {
		r.logger.Errorf("AppointmentHandler.DeleteAppointmentsByAccommodationIDs : Error sending accommodation request")
		span.SetStatus(codes.Error, "Error sending accommodation request")
		rw.Write([]byte("Error sending accommodation request"))
		return
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		r.logger.Errorf("AppointmentHandler.DeleteAppointmentsByAccommodationIDs : Accommodation service returned an error")
		span.SetStatus(codes.Error, "Accommodation service returned an error")
		rw.Write([]byte("Accommodation service returned an error"))
		return
	}

	var accommodations []primitive.ObjectID

	fmt.Println("lola", accommodations)
	err = json.NewDecoder(accommodationResponse.Body).Decode(&accommodations)
	if err != nil {
		r.logger.Errorf("AppointmentHandler.DeleteAppointmentsByAccommodationIDs : Error decoding accommodation response")
		span.SetStatus(codes.Error, "Error decoding accommodation response")
		rw.Write([]byte("Error decoding accommodation response"))
		return
	}

	defer accommodationResponse.Body.Close()
	for _, accommodationID := range accommodations {

		err := r.appointmentRepo.DeleteAppointmentsByAccommodationID(ctx, accommodationID.Hex())
		if err != nil {
			r.logger.Errorf("AppointmentHandler.DeleteAppointmentsByAccommodationIDs : Error deleting appointments")
			span.SetStatus(codes.Error, "Error deleting appointments")
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte("Error deleting appointments"))
			return
		}
		return
	}

	r.logger.Infoln("AppointmentHandler.DeleteAppointmentsByAccommodationIDs : DeleteAppointmentsByAccommodationIDs finished")
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("Appointments deleted successfully"))
}

func (r *AppointmentHandler) FilterAppointmentsByPrice(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.FilterAppointmentsByPrice")
	defer span.End()

	r.logger.Infoln("AppointmentHandler.FilterAppointmentsByPrice : FilterAppointmentsByPrice endpoint reached")

	minPriceStr := h.URL.Query().Get("minPrice")
	maxPriceStr := h.URL.Query().Get("maxPrice")

	var minPrice, maxPrice float64
	var err error

	if minPriceStr != "" {
		minPrice, err = strconv.ParseFloat(minPriceStr, 64)
		if err != nil {
			r.logger.Errorf("AppointmentHandler.FilterAppointmentsByPrice : Invalid minPrice parameter")
			span.SetStatus(codes.Error, "Invalid minPrice parameter")
			http.Error(rw, "Invalid minPrice parameter", http.StatusBadRequest)
			rw.Write([]byte("Invalid minPrice parameter"))
			return
		}
	}

	if maxPriceStr != "" {
		maxPrice, err = strconv.ParseFloat(maxPriceStr, 64)
		if err != nil {
			r.logger.Errorf("AppointmentHandler.FilterAppointmentsByPrice : Invalid maxPrice parameter")
			span.SetStatus(codes.Error, "Invalid maxPrice parameter")
			http.Error(rw, "Invalid maxPrice parameter", http.StatusBadRequest)
			rw.Write([]byte("Invalid maxPrice parameter"))
			return
		}
	}

	if minPriceStr == "" {
		appointments, err := r.appointmentRepo.FilterAppointmentsByPrice(ctx, -1, int(maxPrice))
		if err != nil {
			r.logger.Errorf("AppointmentHandler.FilterAppointmentsByPrice : Unable to retrieve filtered appointments")
			span.SetStatus(codes.Error, "Unable to retrieve filtered appointments")
			http.Error(rw, "Unable to retrieve filtered appointments", http.StatusInternalServerError)
			return
		}

		if len(appointments) == 0 {
			r.logger.Errorf("AppointmentHandler.FilterAppointmentsByPrice : Status no content")
			rw.WriteHeader(http.StatusNoContent)
			return
		}

		err = appointments.ToJSON(rw)
		if err != nil {
			r.logger.Errorf("AppointmentHandler.FilterAppointmentsByPrice : Unable to convert to JSON")
			span.SetStatus(codes.Error, "Unable to convert to JSON")
			http.Error(rw, "Unable to convert to JSON", http.StatusInternalServerError)
			return
		}

		return
	}

	if maxPriceStr == "" {
		appointments, err := r.appointmentRepo.FilterAppointmentsByPrice(ctx, int(minPrice), -1)
		if err != nil {
			r.logger.Errorf("AppointmentHandler.FilterAppointmentsByPrice : Unable to retrieve filtered appointments")
			span.SetStatus(codes.Error, "Unable to retrieve filtered appointments")
			http.Error(rw, "Unable to retrieve filtered appointments", http.StatusInternalServerError)
			return
		}

		if len(appointments) == 0 {
			r.logger.Errorf("AppointmentHandler.FilterAppointmentsByPrice : Status no content")
			rw.WriteHeader(http.StatusNoContent)
			return
		}

		err = appointments.ToJSON(rw)
		if err != nil {
			r.logger.Errorf("AppointmentHandler.FilterAppointmentsByPrice : Unable to convert to JSON")
			span.SetStatus(codes.Error, "Unable to convert to JSON")
			http.Error(rw, "Unable to convert to JSON", http.StatusInternalServerError)
			return
		}

		return
	}

	if minPriceStr != "" && maxPriceStr != "" {
		appointments, err := r.appointmentRepo.FilterAppointmentsByPrice(ctx, int(minPrice), int(maxPrice))
		if err != nil {
			r.logger.Errorf("AppointmentHandler.FilterAppointmentsByPrice : Unable to retrieve filtered appointments")
			span.SetStatus(codes.Error, "Unable to retrieve filtered appointments")
			http.Error(rw, "Unable to retrieve filtered appointments", http.StatusInternalServerError)
			return
		}

		if len(appointments) == 0 {
			r.logger.Errorf("AppointmentHandler.FilterAppointmentsByPrice : Status no content")
			rw.WriteHeader(http.StatusNoContent)
			return
		}

		err = appointments.ToJSON(rw)
		if err != nil {
			span.SetStatus(codes.Error, "Unable to convert to JSON")
			http.Error(rw, "Unable to convert to JSON", http.StatusInternalServerError)
			r.logger.Fatal("Unable to convert to JSON")
			return
		}
	}
}

func (s *AppointmentHandler) MiddlewareAppointmentDeserialization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, h *http.Request) {
		appointments := &data.Appointment{}
		err := appointments.FromJSON(h.Body)
		if err != nil {
			http.Error(rw, "Unable to decode json", http.StatusBadRequest)
			s.logger.Fatal(err)
			return
		}
		ctx := context.WithValue(h.Context(), KeyProduct{}, appointments)
		h = h.WithContext(ctx)
		next.ServeHTTP(rw, h)
	})
}

func (s *AppointmentHandler) HTTPSRequestWithouthBody(ctx context.Context, token string, url string, method string) (*http.Response, error) {
	clientCertPath := "ca-cert.pem"

	clientCaCert, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(clientCaCert)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		CurvePreferences: []tls.CurveID{tls.CurveP521,
			tls.CurveP384, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return resp, nil
}
