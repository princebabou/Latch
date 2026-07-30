# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.24.13
ARG ALPINE_VERSION=3.23

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION}@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE} -X main.builtBy=docker" \
    -o /out/latch ./cmd/latch
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/latch-demo-mcp ./examples/mcpserver
RUN mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="Latch" \
      org.opencontainers.image.description="Security enforcement layer for AI agents" \
      org.opencontainers.image.source="https://github.com/princebabou/Latch" \
      org.opencontainers.image.url="https://github.com/princebabou/Latch" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=build /out/latch /usr/local/bin/latch
COPY --from=build /out/latch-demo-mcp /usr/local/bin/latch-demo-mcp
COPY --from=build --chown=nonroot:nonroot /out/state /var/lib/latch
COPY configs/latch.identity.example.yaml /etc/latch/latch.yaml

ENV LATCH_CONFIG=/etc/latch/latch.yaml \
    LATCH_AGENT=desktop-agent \
    LATCH_AUDIT_PATH=/var/lib/latch/audit.jsonl \
    LATCH_APPROVAL_STORE=/var/lib/latch/approvals.json \
    LATCH_BUDGET_STORE=/var/lib/latch/budgets.json \
    LATCH_AUDIT_TERMINAL=true

WORKDIR /workspace
VOLUME ["/var/lib/latch"]
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/latch"]
CMD ["doctor"]
