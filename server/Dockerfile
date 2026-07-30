# syntax=docker/dockerfile:1.7

FROM golang:1.26-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/control-plane ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot

ENV PORT=8080
EXPOSE 8080

COPY --from=builder /out/control-plane /control-plane

ENTRYPOINT ["/control-plane"]
