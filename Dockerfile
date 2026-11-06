# --- STAGE 1: Build the binary ---
FROM golang:1.25-bookworm AS builder

# Set working directory
WORKDIR /src

# 1. Copy the local source code into the container
# This copies everything from your current branch/dir into /src
COPY . .

# 2. Download Go dependencies
# It finds go.mod in the root automatically
RUN go mod download

# 3. Build the application statically
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/cheesy-arena .

# --- STAGE 2: Run the binary ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the builder
COPY --from=builder /app/cheesy-arena /app/cheesy-arena

# 4. Copy static assets dynamically
# Since we copied everything to /src in Stage 1, they are right there
COPY --from=builder /src/static /app/static
COPY --from=builder /src/templates /app/templates
COPY --from=builder /src/schedules /app/schedules

RUN chmod +x /app/cheesy-arena

EXPOSE 8080 1160 1750

CMD ["./cheesy-arena"]