FROM --platform=linux/amd64 golang:1.22 AS builder

RUN mkdir /app
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY main.go main.go

RUN CGO_ENABLED=0 GOOS=linux go build -o run-me .


FROM scratch

COPY --from=builder /app/run-me /run-me
ENTRYPOINT ["/run-me"]