package main

import (
	"os"
	"testing"
)

// main 은 성공하면 os.Exit 을 부르지 않으므로 테스트가 부를 수 있다.
// 실패하면 프로세스가 죽어 테스트도 함께 실패하므로, 종료하지 않는
// 인자를 쓴다.
func TestMainEntrypoint(t *testing.T) {
	old := os.Args
	defer func() { os.Args = old }()

	os.Args = []string{"gossl", "--version"}
	main()
}
