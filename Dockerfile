FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ARG TARGETOS
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH=0
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
COPY go.mod ./
COPY cmd/service ./cmd/service
COPY internal/service ./internal/service
RUN --network=none GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/service ./cmd/service

FROM scratch
ARG SOURCE_DATE_EPOCH=0
COPY --from=build --chown=65532:65532 /out/service /service
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/service"]
