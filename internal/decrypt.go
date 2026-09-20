package internal

import (
	"crypto"
	"crypto/dsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type (
	Pem struct {
		Type  string
		Data  []byte
		Block *pem.Block
	}

	Md5 struct {
		Certificate   string
		RsaPrivateKey string
	}
)

func (p Pem) getType() string {
	return p.Type
}

func (p Pem) getData() []byte {
	return p.Data
}

func (p Pem) getBlock() *pem.Block {
	return p.Block
}

func (m Md5) getCertificate() string {
	return m.Certificate
}

func (m Md5) getRsaPrivateKey() string {
	return m.RsaPrivateKey
}

func GetPemType(file string) (*Pem, error) {

	p := &Pem{}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return &Pem{
			Type:  "CRT",
			Data:  data,
			Block: nil,
		}, nil
	} else {
		p.Type = block.Type
		p.Data = data
		p.Block = block
	}

	return &Pem{
		Type:  p.getType(),
		Data:  p.getData(),
		Block: p.getBlock(),
	}, nil
}

func md5Hex(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

// publicKeyFingerprint 는 공개키 하나에 대해 안정적인 지문을 만든다.
// 인증서 쪽과 개인키 쪽이 모두 이 함수를 거치므로, 같은 쌍이면 반드시 같은 값이 나온다.
//
// RSA 는 openssl 의 modulus 표기를 그대로 쓴다. 나머지 알고리즘은 대응하는
// -modulus 출력이 없으므로 PKIX DER 인코딩을 해싱한다.
// 이렇게 해야 곡선 파라미터가 아니라 공개키 자체가 값에 반영된다.
func publicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		// openssl 은 "Modulus=<HEX>" 뒤의 개행까지 포함해 해시한다.
		modulus := strings.ToUpper(hex.EncodeToString(k.N.Bytes()))
		return md5Hex([]byte(fmt.Sprintf("Modulus=%s\n", modulus))), nil
	case *dsa.PublicKey:
		// DSA 는 MarshalPKIXPublicKey 가 지원하지 않는다.
		if k.Y == nil {
			return "", fmt.Errorf("dsa public key has no Y value")
		}
		modulus := strings.ToUpper(hex.EncodeToString(k.Y.Bytes()))
		return md5Hex([]byte(fmt.Sprintf("Modulus=%s\n", modulus))), nil
	default:
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", fmt.Errorf("unsupported public key algorithm: %w", err)
		}
		return md5Hex(der), nil
	}
}

func GetMd5FromCertificate(p *Pem) (*Md5, error) {

	if p == nil || p.getBlock() == nil {
		return nil, fmt.Errorf("no PEM block found, this file may be DER encoded")
	}

	cert, err := x509.ParseCertificate(p.getBlock().Bytes)
	if err != nil {
		return nil, err
	}

	fingerprint, err := publicKeyFingerprint(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	m := &Md5{}
	m.Certificate = fingerprint

	return &Md5{
		Certificate: m.getCertificate(),
	}, nil
}

// parsePrivateKey 는 PKCS#1, PKCS#8, SEC1(EC) 순으로 시도한다.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("failed to parse private key as PKCS#1, PKCS#8 or SEC1")
}

func privateKeyFingerprint(der []byte) (string, error) {
	key, err := parsePrivateKey(der)
	if err != nil {
		return "", err
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("unsupported private key type %T", key)
	}
	return publicKeyFingerprint(signer.Public())
}

func GetMd5FromRsaPrivateKey(p *Pem) (*Md5, error) {

	if p == nil || p.getBlock() == nil {
		return nil, fmt.Errorf("no PEM block found in private key file")
	}

	m := &Md5{}
	block := p.getBlock()
	der := block.Bytes

	if x509.IsEncryptedPEMBlock(block) {
		password, err := AskInput("What is your password", 1)
		if err != nil {
			return nil, err
		}

		decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
		der = decrypted
	}

	fingerprint, err := privateKeyFingerprint(der)
	if err != nil {
		return nil, err
	}
	m.RsaPrivateKey = fingerprint

	return &Md5{
		RsaPrivateKey: m.getRsaPrivateKey(),
	}, nil
}

func PrivateToRsaPrivate(newFileName string, pemBlock *pem.Block) error {
	if pemBlock == nil {
		return fmt.Errorf("no PEM block found in private key file")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return err
	}

	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("this key is %T, only RSA keys can be converted to RSA PRIVATE KEY", parsed)
	}

	newFile, err := os.Create(newFileName)
	if err != nil {
		return err
	}
	defer newFile.Close()

	if err := pem.Encode(newFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}); err != nil {
		return err
	}

	return newFile.Close()
}

func CrtToCertificate(fileName string, bytes []byte) error {
	crt, err := x509.ParseCertificate(bytes)
	if err != nil {
		return err
	}

	// 첫 점이 아니라 마지막 확장자만 바꾼다. my.site.2026.crt -> my.site.2026.pem
	newFileName := strings.TrimSuffix(fileName, filepath.Ext(fileName)) + ".pem"
	newFile, err := os.Create(newFileName)
	if err != nil {
		return err
	}
	defer newFile.Close()

	if err := pem.Encode(newFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt.Raw,
	}); err != nil {
		return err
	}

	return newFile.Close()
}
