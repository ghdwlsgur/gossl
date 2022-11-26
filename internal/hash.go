package internal

import (
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
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
		return nil, fmt.Errorf("%s's pem block is empty, check certificate type", file)
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

func GetMd5FromCertificate(p *Pem) (*Md5, error) {

	m := &Md5{}
	cert, err := x509.ParseCertificate(p.getBlock().Bytes)
	if err != nil {
		return nil, err
	}

	pubKey := cert.PublicKey.(*rsa.PublicKey).N
	modulus := strings.ToUpper(hex.EncodeToString(pubKey.Bytes()))
	mdl := fmt.Sprintf("Modulus=%s", modulus)

	hash := md5.New()
	hash.Write([]byte(mdl))
	m.Certificate = hex.EncodeToString(hash.Sum(nil))

	return &Md5{
		Certificate: m.getCertificate(),
	}, nil
}

func GetMd5FromRsaPrivateKey(p *Pem) (*Md5, error) {

	m := &Md5{}
	block := p.getBlock()
	enc := x509.IsEncryptedPEMBlock(block)

	if enc {
		password, err := AskInput("What is your password", 1)
		if err != nil {
			return nil, err
		}

		b, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}

		priv, err := x509.ParsePKCS1PrivateKey(b)
		if err != nil {
			return nil, err
		}

		modulus := strings.ToUpper(hex.EncodeToString(priv.N.Bytes()))
		mdl := fmt.Sprintf("Modulus=%s", modulus)

		hash := md5.New()
		hash.Write([]byte(mdl))
		m.RsaPrivateKey = hex.EncodeToString(hash.Sum(nil))
	} else {

		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		modulus := strings.ToUpper(hex.EncodeToString(priv.N.Bytes()))
		mdl := fmt.Sprintf("Modulus=%s", modulus)

		hash := md5.New()
		hash.Write([]byte(mdl))
		m.RsaPrivateKey = hex.EncodeToString(hash.Sum(nil))
	}

	return &Md5{
		RsaPrivateKey: m.getRsaPrivateKey(),
	}, nil
}
