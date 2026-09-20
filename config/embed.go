// Package config 는 바이너리에 함께 실리는 데이터를 담는다.
package config

import _ "embed"

//go:generate go run ../tools/genroots -o roots.pem

// Roots 는 download 명령이 제시하는 루트 인증서 번들이다.
//
// tools/genroots 가 CCADB(Mozilla 가 운영하고 Google, Apple, Microsoft 가
// 함께 쓰는 루트 인증서 데이터베이스)에서 생성한다. 직접 고치지 않는다.
//
// 예전에는 손으로 관리한 이름과 벤더 URL 목록을 썼다. 갱신이 3년 멈춰
// 항목의 85% 가 루트 프로그램에서 빠진 인증서였고, 일부는 이미 만료되었으며
// URL 이 죽은 것도 있었다.
//
//go:embed roots.pem
var Roots []byte
