FROM golang:latest AS builder
WORKDIR /app
COPY ./auth_service/go.mod ./auth_service/go.sum ./
RUN go mod download
COPY ./auth_service/ .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
COPY /auth_service/blacklist.txt .
COPY /rbac_model/rbac_model.conf/ .
COPY /auth_service/policy.csv .
COPY /api_gateway/cert/auth_service/auth_service-cert.pem .
COPY /api_gateway/cert/auth_service/auth_service-key.pem .
COPY /api_gateway/cert/airbnb_ca/ca-cert.pem .
EXPOSE 8009
CMD ["./main", "server", "https"]