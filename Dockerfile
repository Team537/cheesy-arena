# --- STAGE 1: Build the binary ---
FROM golang:1.25-bookworm AS builder

# Install git
RUN apt-get update && apt-get install -y git

# Set working directory
WORKDIR /src

# 1. Clone the repository
RUN git clone https://github.com/knauerhd/cheesy-arena.git

# --- FIX: Change directory to where the code actually lives ---
WORKDIR /src/cheesy-arena

# 2. Download Go dependencies
RUN go mod download

# 3. Build the application statically
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/cheesy-arena .

# --- STAGE 2: Run the binary ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/cheesy-arena /app/cheesy-arena

# --- FIX: Update paths to reflect the subfolder location ---
COPY --from=builder /src/cheesy-arena/static /app/static
COPY --from=builder /src/cheesy-arena/templates /app/templates
COPY --from=builder /src/cheesy-arena/schedules /app/schedules

RUN chmod +x /app/cheesy-arena

EXPOSE 8080 1160 1750

CMD ["./cheesy-arena"]