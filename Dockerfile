# --- Build Stage ---
FROM --platform=linux/amd64 golang:1.23-bookworm AS builder

# Install Go, libpcap-dev, gcc, and CA certificates
RUN apt-get update && \
    apt-get install -y gcc g++ gcc-multilib libpcap-dev sqlite3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Set environment for CGO-enabled cross-compilation
ENV CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64

# Set the working directory inside the container
WORKDIR /app

# Copy go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the Go application 
RUN go build -o traffic-sensor ./cmd/traffic-sensor

# --- Runtime Stage ---
FROM --platform=linux/amd64 debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y libpcap0.8 ca-certificates sqlite3 && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the compiled binary from the builder
COPY --from=builder /app/traffic-sensor .

# Default command
CMD ["./traffic-sensor"]
