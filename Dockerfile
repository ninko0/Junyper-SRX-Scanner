# --- build stage ---
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/srxtool-server ./cmd/server

# --- final stage ---
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/srxtool-server /srxtool-server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/srxtool-server"]
