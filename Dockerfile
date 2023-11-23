FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.21.4 as builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

ARG Version
ARG GitCommit

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download
COPY internal ./internal/
COPY main.go ./

# run all our tests
RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go test -v ./...

RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -o /step-posture-connector

FROM --platform=${BUILDPLATFORM:-linux/amd64} gcr.io/distroless/base-debian12:nonroot
#
WORKDIR /
COPY --from=builder /step-posture-connector /
USER nonroot:nonroot

EXPOSE 9443

CMD ["/step-posture-connector"]