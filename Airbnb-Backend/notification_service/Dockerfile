FROM golang:latest as builder
WORKDIR /app
COPY ./notification_service/go.mod ./notification_service/go.sum ./
RUN go mod download
COPY ./notification_service/ .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/main .
COPY /rbac_model/rbac_model.conf/ .
COPY /notification_service/policy.csv .
EXPOSE 8000
CMD ["./main"]
