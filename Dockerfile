FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/idp ./cmd/idp
FROM alpine:3.20
RUN adduser -D -H idp && mkdir -p /data && chown idp:idp /data
COPY --from=build /out/idp /usr/local/bin/idp
USER idp
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/idp"]
