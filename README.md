<div align="center">

<br>
<br>

<img width="50%" alt="govpn-logo" src="https://user-images.githubusercontent.com/77400522/202766468-72b9c4ac-2191-4c8d-945e-97d96a75c3aa.png">

![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/ghdwlsgur/gossl?color=success&label=version&sort=semver)
[![Go Report Card](https://goreportcard.com/badge/github.com/ghdwlsgur/gossl)](https://goreportcard.com/report/github.com/ghdwlsgur/gossl)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/77e2268c53a34ac7ae629a09e63c4419)](https://www.codacy.com/gh/ghdwlsgur/gossl/dashboard?utm_source=github.com&utm_medium=referral&utm_content=ghdwlsgur/gossl&utm_campaign=Badge_Grade)
[![Maintainability](https://api.codeclimate.com/v1/badges/1d8e562559047191efd8/maintainability)](https://codeclimate.com/github/ghdwlsgur/gossl/maintainability)

</div>

# Overview

An interactive cli tool that easily binds HTTPS certificates and diagnoses whether certificates are applied with edge servers as proxy.

# Why

It was inconvenient to memorize the file name by checking the type of file for the Certificate Chain of Trust and integrate the files in the order of leaf, intermediate, and root with the cat command.

```bash
cat leaf.crt intermediate.crt root.crt > new.pem
```

I had to check md5 every time by adding an option to the openssl command.

```bash
echo | openssl x509 -in leaf.crt -modulus -noout
```

I had to proxy to the origin domain's A record address to get a response from the target domain's content, as in the example below.

```bash
curl -vo /dev/null -H 'Range:bytes=0-1' --resolve 'naver.com:443:223. 130.195.95' 'https://www.naver.com/include/themecast/targetAndPanels.json'
```

Therefore, gossl is an interactive tool designed to conveniently use certificate integration by selecting and checking only the fields you want without using long commands.

# Installation

### homebrew

```bash

# [install]
brew tap ghdwlsgur/gossl
brew install gossl

# [upgrade]
brew upgrade gossl
```

### [Download](https://github.com/ghdwlsgur/gossl/releases)

# Workflow

> Describe the workflow with gossl command arguments.

### `echo` -> `merge` -> `zip` -> `connect`

### echo

- Check the type of each certificate file and compare the md5 hash values.

### merge

- Combine the verified certificate files in the order of leaf, intermediate, and root.

### zip

- Compress the merged certificate file and rsa private key into a zip file.

### connect

- You get a response from the target domain by proxying it to the a record address of the domain you are using the https protocol.

# How to use

In the command, go to the folder path where the certificate is located.

```bash
pwd
/Users/jinhyeokhong/playground/gossl-example-crt

ls
intermediate.crt
leaf.crt
root.crt
rsa_private.key
```

### `echo`

```bash
gossl echo
```

### Response Field

if Type == CERTIFICATE {

- pem.block
- VerifyHostName
- Issuer Name
- Expire Date
- Type
- Detail
- Md5 Hash

}

if Type == RSA PRIVATE KEY {

- pem.block
- Type
- Md5 Hash

}

### Example

<p align="center">
<img src="https://user-images.githubusercontent.com/77400522/202838670-ce5fed38-bd4f-4800-bf0c-fe29197109bb.mov" width="680", height="550" />
</p>

---

# License

gossl is licensed under the [MIT](https://github.com/ghdwlsgur/gossl/blob/master/LICENSE)
