FROM golang:alpine AS builder

RUN apk add --no-cache --update git build-base
ENV CGO_ENABLED=0

WORKDIR /app

COPY . /app

WORKDIR /app/src
ARG BUILD_VERSION=0.0.0-dev
RUN go mod download
RUN go build -trimpath -ldflags="-s -w -X github.com/GMWalletApp/epusdt/config.BuildVersion=${BUILD_VERSION}" -o /app/epusdt .

FROM alpine:latest AS runner
ENV TZ=Asia/Shanghai
# The first-run wizard binds loopback by default. A container is normally installed
# through its published port, so the image opts in explicitly here; overriding this
# to an empty value keeps the wizard local to the container.
ENV EPUSDT_INSTALL_ADDR=:8000
RUN apk --no-cache add ca-certificates tzdata
ARG API_RATE_URL=""

WORKDIR /app
COPY --from=builder /app/src/.env.example /app/.env
RUN if [ -n "$API_RATE_URL" ]; then \
      sed -i "s|^api_rate_url=.*$|api_rate_url=${API_RATE_URL}|" /app/.env; \
    fi
COPY --from=builder /app/epusdt .

VOLUME /app/conf
ENTRYPOINT ["./epusdt", "http", "start"]
