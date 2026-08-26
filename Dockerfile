FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/sroiaaa-agent ./cmd/sroiaaa-agent

FROM alpine:3.22

RUN addgroup -S sroiaaa && adduser -S -G sroiaaa -u 10001 sroiaaa
WORKDIR /app
COPY --from=build /out/sroiaaa-agent /usr/local/bin/sroiaaa-agent
USER sroiaaa
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/sroiaaa-agent"]
