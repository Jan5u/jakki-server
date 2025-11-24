FROM golang:1.25.1-trixie AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY database/ database/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o bin/jakkiserver cmd/jakki/main.go


FROM scratch
WORKDIR /app
COPY --from=build /build/bin/jakkiserver bin/jakkiserver
COPY LICENSE /LICENSE
EXPOSE 7777/udp
ENTRYPOINT ["bin/jakkiserver"]