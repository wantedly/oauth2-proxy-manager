FROM golang:1.20 AS build
WORKDIR /go/src/github.com/wantedly/oauth2-proxy-manager

ENV GOOS linux
ENV CGO_ENABLED 0

ADD go.sum go.sum
ADD go.mod go.mod
RUN go mod download
COPY . .
RUN go build -a -installsuffix cgo -v -o create-oauth2-proxy ./showcase/create-oauth2-proxy/main.go

FROM alpine
WORKDIR /app

EXPOSE 8080
COPY --from=build /go/src/github.com/wantedly/oauth2-proxy-manager/create-oauth2-proxy /app/

ENTRYPOINT ["/app/create-oauth2-proxy"]
