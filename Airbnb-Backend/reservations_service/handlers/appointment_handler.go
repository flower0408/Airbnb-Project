package handlers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
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
	"strings"
	"time"
)

type AppointmentHandler struct {
	logger          *log.Logger
	appointmentRepo *data.AppointmentRepo
	tracer          trace.Tracer
}

var (
	accommodationServiceHost = os.Getenv("ACCOMMODATIONS_SERVICE_HOST")
	accommodationServicePort = os.Getenv("ACCOMMODATIONS_SERVICE_PORT")
)

func NewAppointmentHandler(l *log.Logger, r *data.AppointmentRepo, t trace.Tracer) *AppointmentHandler {
	return &AppointmentHandler{l, r, t}
}

// mongo
func (r *AppointmentHandler) CreateAppointment(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.CreateAppointment")
	defer span.End()

	appointment := h.Context().Value(KeyProduct{}).(*data.Appointment)
	err := r.appointmentRepo.InsertAppointment(ctx, appointment)
	if err != nil {
		span.SetStatus(codes.Error, "Error creating appointment")
		if err.Error() == "Error adding appointment. Date already exists. " {
			r.logger.Print("Error adding appointment. Date already exists. ")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error adding appointment. Date already exists. "))
		} else if err.Error() == "Error adding appointment. Cannot add appointment in the past." {
			r.logger.Print("Error adding appointment. Cannot add appointment in the past.")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error adding appointment. Cannot add appointment in the past."))
		} else {
			r.logger.Print("Database exception: ", err)
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error creating reservation."))
		}
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (r *AppointmentHandler) GetAllAppointment(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.GetAllAppointment")
	defer span.End()

	appointments, err := r.appointmentRepo.GetAllAppointment(ctx)
	if err != nil {
		span.SetStatus(codes.Error, "Database exception")
		r.logger.Print("Database exception")
	}

	if appointments == nil {
		return
	}

	err = appointments.ToJSON(rw)
	if err != nil {
		span.SetStatus(codes.Error, "Unable to convert to json")
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		r.logger.Fatal("Unable to convert to json")
		return
	}
}

func (r *AppointmentHandler) GetAppointmentsByAccommodation(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.GetAppointmentsByAccommodation")
	defer span.End()

	vars := mux.Vars(h)
	id := vars["id"]

	appointments, err := r.appointmentRepo.GetAppointmentsByAccommodation(ctx, id)
	if err != nil {
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
		span.SetStatus(codes.Error, "Unable to convert to json")
		http.Error(rw, "Unable to convert to json", http.StatusInternalServerError)
		r.logger.Fatal("Unable to convert to json")
		return
	}
}

func (r *AppointmentHandler) GetAppointmentsByDate(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.GetAppointmentsByDate")
	defer span.End()

	startDateStr := h.URL.Query().Get("startDate")
	endDateStr := h.URL.Query().Get("endDate")

	startDate, err := time.Parse(time.RFC3339, startDateStr)
	if err != nil {
		span.SetStatus(codes.Error, "Invalid startDate parameter")
		http.Error(rw, "Invalid startDate parameter", http.StatusBadRequest)
		return
	}

	endDate, err := time.Parse(time.RFC3339, endDateStr)
	if err != nil {
		span.SetStatus(codes.Error, "Invalid endDate parameter")
		http.Error(rw, "Invalid endDate parameter", http.StatusBadRequest)
		return
	}

	appointments, err := r.appointmentRepo.GetAppointmentsByDate(ctx, startDate, endDate)
	if err != nil {
		span.SetStatus(codes.Error, "Unable to retrieve appointments")
		r.logger.Print("Database exception")
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
		span.SetStatus(codes.Error, "Unable to convert to JSON")
		http.Error(rw, "Unable to convert to JSON", http.StatusInternalServerError)
		r.logger.Fatal("Unable to convert to JSON")
		return
	}
}

func (r *AppointmentHandler) UpdateAppointment(rw http.ResponseWriter, h *http.Request) {
	ctx, span := r.tracer.Start(h.Context(), "AppointmentHandler.UpdateAppointment")
	defer span.End()

	vars := mux.Vars(h)
	id := vars["id"]

	appointment := h.Context().Value(KeyProduct{}).(*data.Appointment)

	tokenString, err := extractTokenFromHeader(h)
	if err != nil {
		span.SetStatus(codes.Error, "No token found")
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("No token found"))
		return
	}

	err = r.appointmentRepo.UpdateAppointment(ctx, id, appointment, tokenString)
	if err != nil {
		span.SetStatus(codes.Error, "Error update appointment")
		if err.Error() == "Reservation exists for the appointment." {
			rw.WriteHeader(http.StatusMethodNotAllowed)
			rw.Write([]byte("Reservation exists for the appointment. Update not allowed."))
		} else if err.Error() == "Error editing appointment. Date already exists. " {
			r.logger.Print("Error editing appointment. Date already exists. ")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error editing appointment. Date already exists. "))
		} else if err.Error() == "Error editing appointment. Cannot add appointment in the past." {
			r.logger.Print("Error editing appointment. Cannot add appointment in the past.")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error editing appointment. Cannot add appointment in the past."))
		} else {
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte("Error updating appointment."))
		}
		return
	}

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

	vars := mux.Vars(h)
	userId := vars["id"]

	authHeader := h.Header.Get("Authorization")
	authToken := extractBearerToken(authHeader)

	if authToken == "" {
		span.SetStatus(codes.Error, "Error extracting Bearer token")
		r.logger.Println("Error extracting Bearer token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	accommodationEndpoint := fmt.Sprintf("https://%s:%s/owner/%s", accommodationServiceHost, accommodationServicePort, userId)
	accommodationResponse, err := r.HTTPSRequestWithouthBody(ctx, authToken, accommodationEndpoint, "GET")
	if err != nil {
		span.SetStatus(codes.Error, "Error sending accommodation request")
		r.logger.Println("Error sending accommodation request:", err)
		rw.Write([]byte("Error sending accommodation request"))
		return
	}

	if accommodationResponse.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, "Accommodation service returned an error")
		r.logger.Println("Accommodation service returned an error:", accommodationResponse.Status)
		rw.Write([]byte("Accommodation service returned an error"))
		return
	}

	var accommodations []primitive.ObjectID

	fmt.Println("lola", accommodations)
	err = json.NewDecoder(accommodationResponse.Body).Decode(&accommodations)
	if err != nil {
		span.SetStatus(codes.Error, "Error decoding accommodation response")
		r.logger.Println("Error decoding accommodation response:", err)
		rw.Write([]byte("Error decoding accommodation response"))
		return
	}

	defer accommodationResponse.Body.Close()
	for _, accommodationID := range accommodations {

		err := r.appointmentRepo.DeleteAppointmentsByAccommodationID(ctx, accommodationID.Hex())
		if err != nil {
			span.SetStatus(codes.Error, "Error deleting appointments")
			r.logger.Print("Database exception:", err)
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte("Error deleting appointments"))
			return
		}
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("Appointments deleted successfully"))
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
		PreferServerCipherSuites: true,
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
