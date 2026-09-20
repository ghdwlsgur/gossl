#!/usr/bin/env bash
set -e -o pipefail

trap '[ "$?" -eq 0 ] || echo "Error Line:<$LINENO> Error Function:<${FUNCNAME}>"' EXIT
cd "$(dirname "$0")" && cd ..
CURRENT=$(pwd)

function test
{
    go test -v ./... --count 1 -race -coverprofile="$CURRENT"/coverage.txt -covermode=atomic
}

# 릴리스는 태그를 밀면 .github/workflows/release.yml 이 처리한다.
#   git tag -a v1.2.3 -m "..." && git push origin v1.2.3
# 아래는 발행 없이 산출물만 만들어 확인할 때 쓴다.
function release_test
{
  rm -rf "$CURRENT"/dist
  goreleaser release --snapshot --clean --skip=publish
}

CMD=$1
shift
"$CMD" "$*"
