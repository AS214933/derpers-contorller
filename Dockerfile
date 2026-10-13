ARG NODE_IMAGE=node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402
ARG GOLANG_IMAGE=golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414
ARG ALPINE_IMAGE=alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
FROM ${NODE_IMAGE} AS web
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build
FROM ${GOLANG_IMAGE} AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/controller ./cmd/controller && \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/agent ./cmd/agent
FROM ${ALPINE_IMAGE} AS runtime
RUN apk add --no-cache ca-certificates tzdata curl
WORKDIR /app
FROM runtime AS controller
COPY --from=build /out/controller /usr/local/bin/controller
COPY --from=web /src/web/dist /app/web
ENV WEB_DIR=/app/web
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/controller"]
CMD ["serve"]
FROM runtime AS agent
COPY --from=build /out/agent /usr/local/bin/agent
ENTRYPOINT ["/usr/local/bin/agent"]
