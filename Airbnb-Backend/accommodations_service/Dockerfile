FROM golang:latest as builder
WORKDIR /app
COPY ./accommodations_service/go.mod ./accommodations_service/go.sum ./
RUN go mod download
COPY ./accommodations_service/ .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM alpine:latest
WORKDIR /root/
COPY /rbac_model/rbac_model.conf/ .
COPY /accommodations_service/policy.csv .
COPY --from=builder /app/main .
EXPOSE 8000
CMD ["./main"]
