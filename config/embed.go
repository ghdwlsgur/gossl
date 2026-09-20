// Package config 는 바이너리에 함께 실리는 설정 데이터를 담는다.
package config

import _ "embed"

// RootSSL 은 download 명령이 제시하는 루트 인증서 목록이다.
//
// 예전에는 이 목록을 실행할 때마다 GitHub Pages 에서 받아왔다. 정확성이
// 외부 호스팅에 묶이고, 저장소 사본과 원격 사본이 갈라져 있었으며,
// 오프라인에서는 동작하지 않았다. 바이너리에 실어 git 에서 버전 관리한다.
//
//go:embed rootSSL.yaml
var RootSSL []byte
