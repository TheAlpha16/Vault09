FROM golang:1.20

RUN mkdir /storage
WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /vault

ENV GIN_MODE=release

CMD ["/vault"]