# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder

WORKDIR /src

# 의존성만 먼저 받아 레이어를 캐시한다. 소스가 바뀌어도 여기는 재사용된다.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# 릴리스 빌드와 같은 방식으로 버전을 주입한다.
ARG VERSION=docker
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -X main.gosslVersion=${VERSION}" \
      -o /out/gossl .

FROM scratch

# 루트 인증서 목록 다운로드와 도메인 TLS 검사에 필요하다.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/gossl /usr/local/bin/gossl

# gossl 은 현재 디렉토리의 pem, crt, key, ca, csr, cer 파일을 훑는다.
# 인증서가 있는 디렉토리를 /work 에 마운트해서 쓴다.
#   docker run --rm -it -v "$PWD:/work" gossl echo
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/gossl"]
