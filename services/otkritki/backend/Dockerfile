FROM golang:1.22 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ENV GOCACHE=/root/.cache/go-build
RUN --mount=type=cache,target="/root/.cache/go-build" go build -o otkritki

FROM ubuntu:22.04
RUN mkdir /app
WORKDIR /app
COPY --from=builder /app/otkritki .
ENTRYPOINT ["./otkritki"]
