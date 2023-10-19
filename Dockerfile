FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN curl -o age -L https://dl.filippo.io/age/latest?for=linux/amd64
RUN CGO_ENABLED=0 go build

FROM scratch
COPY --from=builder /app/secrets /secrets
COPY --from=builder /app/age /bin/age
ENV PATH=/bin
ENTRYPOINT ["/secrets"]
