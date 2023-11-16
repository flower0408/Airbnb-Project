FROM golang:latest as builder
WORKDIR /app
COPY ./auth_service/go.mod ./auth_service/go.sum ./
RUN go mod download
COPY ./auth_service/ .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/main .
COPY /auth_service/blacklist.txt .
EXPOSE 8000
CMD ["./main"]