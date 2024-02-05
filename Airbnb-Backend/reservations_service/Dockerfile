FROM golang:latest AS builder
WORKDIR /app
COPY ./reservations_service/go.mod ./reservations_service/go.sum ./
RUN go mod download
COPY ./reservations_service/ .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY /rbac_model/rbac_model.conf/ .
COPY /reservations_service/policy.csv .
COPY --from=builder /app/main .
COPY /api_gateway/cert/reservations_service/reservations_service-cert.pem .
COPY /api_gateway/cert/reservations_service/reservations_service-key.pem .
COPY /api_gateway/cert/airbnb_ca/ca-cert.pem .
EXPOSE 8009
CMD ["./main", "server", "https"]