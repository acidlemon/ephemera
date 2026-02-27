# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Download dependencies (for better layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build statically linked binary
# CGO_ENABLED=0: Disable cgo for static linking
# -ldflags="-s -w": Strip debug info and symbol table to reduce binary size
# -trimpath: Remove file path information
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -trimpath \
    -o ephemera \
    .

# Runtime stage
FROM alpine:3

# Install runtime dependencies (CA certs for HTTPS, timezone data)
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser

WORKDIR /app

# Copy binary from build stage
COPY --from=builder /build/ephemera .

# Switch to non-root user
USER appuser

# Default port (can be overridden via environment variable)
ENV PORT=5003

# Expose port
EXPOSE ${PORT}

# Run the application
ENTRYPOINT ["/app/ephemera"]
