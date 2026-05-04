FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o policy ./cmd/policy

FROM alpine:3.20
COPY --from=builder /app/policy /policy
EXPOSE 50052
ENTRYPOINT ["/policy"]
