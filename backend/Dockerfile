FROM golang:1.19-alpine

WORKDIR /app

COPY go.mod ./
COPY *.go ./

RUN go mod download
RUN go build -o zein-security .

EXPOSE 8080 9090

CMD ["./zein-security"]