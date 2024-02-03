FROM golang:latest as builder
WORKDIR /app
COPY ./user_service/go.mod ./user_service/go.sum ./
RUN go mod download
COPY ./user_service/ .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
COPY /rbac_model/rbac_model.conf/ .
COPY /user_service/policy.csv .
COPY /api_gateway/cert/user_service/user_service-cert.pem .
COPY /api_gateway/cert/user_service/user_service-key.pem .
COPY /api_gateway/cert/airbnb_ca/ca-cert.pem .
EXPOSE 8009
CMD ["./main", "server", "https"]