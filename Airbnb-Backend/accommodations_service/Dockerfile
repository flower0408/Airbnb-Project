FROM golang:latest as builder
WORKDIR /app
COPY ./accommodations_service/go.mod ./accommodations_service/go.sum ./
RUN go mod download
COPY ./accommodations_service/ .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY /rbac_model/rbac_model.conf/ .
COPY /accommodations_service/policy.csv .
COPY --from=builder /app/main .
COPY /api_gateway/cert/accommodations_service/accommodations_service-cert.pem .
COPY /api_gateway/cert/accommodations_service/accommodations_service-key.pem .
COPY /api_gateway/cert/airbnb_ca/ca-cert.pem .
EXPOSE 8009
CMD ["./main", "server", "https"]