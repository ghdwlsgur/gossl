package internal

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chdir 은 테스트 동안 작업 디렉토리를 옮기고 끝나면 되돌린다.
// DirGrepZip 과 DirGrepX509 가 "./" 를 읽으므로 필요하다.
func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCertFileAccessors(t *testing.T) {
	c := &CertFile{Name: []string{"a.pem", "b.crt"}, Extension: "pem"}
	if got := GetCertExtension(c); got != "pem" {
		t.Errorf("GetCertExtension = %q, 기대 pem", got)
	}
	if got := c.getCertFileLength(); got != 2 {
		t.Errorf("getCertFileLength = %d, 기대 2", got)
	}

	for _, tc := range []struct{ file, want string }{
		{"server.crt", "crt"},
		{"my.site.2026.pem", "pem"},
		{"noext", "noext"},
		{"a.b.c.key", "key"},
	} {
		SetCertExtension(c, tc.file)
		if got := GetCertExtension(c); got != tc.want {
			t.Errorf("SetCertExtension(%q) => %q, 기대 %q", tc.file, got, tc.want)
		}
	}
}

func TestZipFileLength(t *testing.T) {
	z := &ZipFile{Name: []string{"a.zip"}}
	if got := z.getZipFileLength(); got != 1 {
		t.Errorf("getZipFileLength = %d, 기대 1", got)
	}
	if got := (&ZipFile{}).getZipFileLength(); got != 0 {
		t.Errorf("빈 ZipFile = %d, 기대 0", got)
	}
}

func TestDirGrepX509(t *testing.T) {
	dir := t.TempDir()
	// 대상 확장자 6종과 무관한 파일을 섞어 둔다.
	writeFiles(t, dir, "a.pem", "b.crt", "c.key", "d.ca", "e.csr", "f.cer",
		"ignore.txt", "ignore.go", "noext")
	if err := os.Mkdir(filepath.Join(dir, "sub.pem"), 0o755); err != nil {
		t.Fatal(err)
	}
	chdir(t, dir)

	got, err := DirGrepX509()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Name) != 6 {
		t.Errorf("찾은 파일 %d개 (%v), 기대 6개", len(got.Name), got.Name)
	}
	for _, n := range got.Name {
		if strings.HasPrefix(n, "ignore") || n == "noext" || n == "sub.pem" {
			t.Errorf("대상이 아닌 %q 가 포함됐다", n)
		}
	}
}

func TestDirGrepX509_NoMatch(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "readme.md")
	chdir(t, dir)

	if _, err := DirGrepX509(); err == nil {
		t.Error("대상 파일이 없는데 오류를 반환하지 않았다")
	}
}

func TestDirGrepZip(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "a.zip", "b.zip", "c.tar")
	chdir(t, dir)

	got, err := DirGrepZip()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Name) != 2 {
		t.Errorf("찾은 파일 %d개 (%v), 기대 2개", len(got.Name), got.Name)
	}
}

func TestDirGrepZip_NoMatch(t *testing.T) {
	chdir(t, t.TempDir())
	if _, err := DirGrepZip(); err == nil {
		t.Error("zip 이 없는데 오류를 반환하지 않았다")
	}
}

func TestAppendFileAndUnZip(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	writeFiles(t, dir, "one.pem", "two.crt")

	// 압축
	archivePath := filepath.Join(dir, "bundle.zip")
	out, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(out)
	for _, n := range []string{"one.pem", "two.crt"} {
		if err := AppendFile(n, zw); err != nil {
			t.Fatalf("AppendFile(%s): %v", n, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	out.Close()

	// 해제
	dst := filepath.Join(dir, "extracted")
	if err := UnZip(archivePath, dst); err != nil {
		t.Fatalf("UnZip: %v", err)
	}
	for _, n := range []string{"one.pem", "two.crt"} {
		if _, err := os.Stat(filepath.Join(dst, n)); err != nil {
			t.Errorf("해제된 파일이 없다: %s", n)
		}
	}
}

func TestAppendFile_Missing(t *testing.T) {
	buf, err := os.Create(filepath.Join(t.TempDir(), "x.zip"))
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()
	zw := zip.NewWriter(buf)
	defer zw.Close()

	if err := AppendFile(filepath.Join(t.TempDir(), "nope.pem"), zw); err == nil {
		t.Error("없는 파일인데 오류를 반환하지 않았다")
	}
}

func TestUnZip_Errors(t *testing.T) {
	dir := t.TempDir()

	t.Run("존재하지 않는 아카이브", func(t *testing.T) {
		if err := UnZip(filepath.Join(dir, "nope.zip"), dir); err == nil {
			t.Error("오류를 반환하지 않았다")
		}
	})

	t.Run("빈 아카이브", func(t *testing.T) {
		p := filepath.Join(dir, "empty.zip")
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		zip.NewWriter(f).Close()
		f.Close()
		// 빈 zip 은 22바이트(End of Central Directory) 뿐이다.
		if err := UnZip(p, dir); err == nil {
			t.Error("빈 아카이브인데 오류를 반환하지 않았다")
		}
	})
}
