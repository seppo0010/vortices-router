FROM golang:latest
WORKDIR /app
RUN apt-get update && apt-get install -y libpcap-dev iptables libnetfilter-queue-dev
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .
RUN setcap cap_net_raw=+ep /app/main
CMD ["./main"]
