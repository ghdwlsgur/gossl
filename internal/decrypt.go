package internal

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
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

func GetMd5FromCertificate(p *Pem) (*Md5, error) {

	cert, err := x509.ParseCertificate(p.getBlock().Bytes)
	if err != nil {
		return nil, err
	}

	var pubKey *big.Int

	switch cert.PublicKeyAlgorithm.String() {
	case "RSA":
		pubKey = cert.PublicKey.(*rsa.PublicKey).N
	case "ECDSA":
		pubKey = cert.PublicKey.(*ecdsa.PublicKey).Params().N
	case "DSA":
		pubKey = cert.PublicKey.(*dsa.PublicKey).Y
	}

	modulus := strings.ToUpper(hex.EncodeToString(pubKey.Bytes()))
	mdl := fmt.Sprintf("Modulus=%s", modulus)

	hash := md5.New()
	hash.Write([]byte(mdl))

	m := &Md5{}
	m.Certificate = hex.EncodeToString(hash.Sum(nil))

	return &Md5{
		Certificate: m.getCertificate(),
	}, nil
}

func GetMd5FromRsaPrivateKey(p *Pem) (*Md5, error) {

	m := &Md5{}
	block := p.getBlock()
	isEncrypted := x509.IsEncryptedPEMBlock(block)

	if isEncrypted {
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

func PrivateToRsaPrivate(newFileName string, pemBlock *pem.Block) error {
	priv, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return err
	}

	newFile, err := os.Create(newFileName)
	if err != nil {
		return err
	}
	defer newFile.Close()

	pem.Encode(newFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey)),
	})
	return nil
}

func CrtToCertificate(FileName string, bytes []byte) error {
	crt, err := x509.ParseCertificate(bytes)
	if err != nil {
		return err
	}

	newFileName := fmt.Sprintf(strings.Split(FileName, ".")[0] + ".pem")
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

	return nil
}
