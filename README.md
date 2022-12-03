<div align="center">

<br>
<br>

<img width="50%" alt="govpn-logo" src="https://user-images.githubusercontent.com/77400522/202766468-72b9c4ac-2191-4c8d-945e-97d96a75c3aa.png">

![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/ghdwlsgur/gossl?color=success&label=version&sort=semver)
[![Go Report Card](https://goreportcard.com/badge/github.com/ghdwlsgur/gossl)](https://goreportcard.com/report/github.com/ghdwlsgur/gossl)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/77e2268c53a34ac7ae629a09e63c4419)](https://www.codacy.com/gh/ghdwlsgur/gossl/dashboard?utm_source=github.com&utm_medium=referral&utm_content=ghdwlsgur/gossl&utm_campaign=Badge_Grade)
[![Maintainability](https://api.codeclimate.com/v1/badges/1d8e562559047191efd8/maintainability)](https://codeclimate.com/github/ghdwlsgur/gossl/maintainability)
[![circle ci](https://circleci.com/gh/ghdwlsgur/gossl.svg?style=svg)](https://circleci.com/gh/ghdwlsgur/gossl)

</div>

# Overview

An Interactive CLI Tool that easily combines or validates https certificates.

# Chain of trust

![스크린샷 2022-11-19 오후 5 26 49](https://user-images.githubusercontent.com/77400522/202842089-542edbb9-4c0a-44cb-93a9-0f3e61dd5ecf.png)

- https://en.wikipedia.org/wiki/Chain_of_trust

A chain of trust is designed to allow multiple users to create and use software on the system, which would be more difficult if all the keys were stored directly in hardware. It starts with hardware that will only boot from software that is digitally signed. The signing authority will only sign boot programs that enforce security, such as only running programs that are themselves signed, or only allowing signed code to have access to certain features of the machine. This process may continue for several layers.

This process results in a chain of trust. The final software can be trusted to have certain properties, because if it had been illegally modified its signature would be invalid, and the previous software would not have executed it. The previous software can be trusted, because it, in turn, would not have been loaded if its signature had been invalid. The trustworthiness of each layer is guaranteed by the one before, back to the trust anchor.

It would be possible to have the hardware check the suitability (signature) for every single piece of software. However, this would not produce the flexibility that a "chain" provides. In a chain, any given link can be replaced with a different version to provide different properties, without having to go all the way back to the trust anchor. This use of multiple layers is an application of a general technique to improve scalability, and is analogous to the use of multiple certificates in a certificate chain.

# Why

It was inconvenient to memorize the file name by checking the type of file for the Certificate Chain of Trust and integrate the files in the order of leaf, intermediate, and root with the cat command.

```bash
cat leaf.crt intermediate.crt root.crt > new.pem
```

I had to check md5 every time by adding an option to the openssl command.

```bash
echo | openssl x509 -in leaf.crt -modulus -noout
```

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

### unzip ➡️ echo ➡️ merge ➡️ zip ➡️ validate

- `unzip`: Unzip the compressed file.

- `echo`: Check the type of each certificate file and compare the md5 hash values.

- `merge`: Combine the verified certificate files in the order of leaf, intermediate, and root.

- `zip`: Compress the merged certificate file and rsa private key into a zip file.

- `validate`: You get a response from the target domain by proxying it to the a record address of the domain you are using the https protocol.

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

## `echo`

```bash
gossl echo
```

<p align="center">
<img src="https://user-images.githubusercontent.com/77400522/202838670-ce5fed38-bd4f-4800-bf0c-fe29197109bb.mov" width="680", height="550" />

### Response Field

> When selecting a certificate file, provide the fields below.

if Type == CERTIFICATE {

- pem.block
- VerifyHostName
- Issuer Name
- Expire Date
- Type: `CERTIFICATE` | `RSA PRIVATE KEY`
- Detail: `LEAF` | `INTERMEDIATE` | `ROOT`
- Md5 Hash

}

> If the selected file is an RSA PRIVATE KEY which is locked with a password, gossl is entered password from the user.

if Type == RSA PRIVATE KEY {

- pem.block
- Type: `CERTIFICATE` | `RSA PRIVATE KEY`
- Md5 Hash

}

---

## `merge`

> If you select the certificate file to integrate regardless of type, the certificate files are integrated in the order of `leaf`, `intermediate`, and `root`.

- A file with a certificate extension must exist in that location.
- You must select at least two and no more than three.

```bash
# [output file name: gossl_merge_output.pem]
gossl merge

# [output file name: test.pem]
gossl merge -n test
```

<p align="center">
<img src="https://user-images.githubusercontent.com/77400522/202840001-74b38122-1164-40dd-a0e5-6153ceeea01c.mov" width="680", height="550" />
</p>

### `zip`

```bash
# [output file name: gossl_zip_output.zip]
gossl zip

# [output file name: test.zip]
gossl zip -n test
```

<p align="center">
<img src="https://user-images.githubusercontent.com/77400522/202840112-1b0b2054-8864-450a-af92-5e6799a2cd9e.mov" width="680", height="550" />
</p>

### `validate`

> Used to verify the application of the certificate to the origin server.

> The -n argument is called the origin domain, and the -t argument is called the target domain.

> -n `argument`: `origin domain` / -t `argument`: `target domain`

- If the target domain is omitted, the origin domain goes in as the target domain.
- Get the response from the target domain by proxying the address of the origin domain's A record
- The two commands below produce the same result.
- For curl you have to manually enter the origin domain's a record, but gossl interactively provides an a record option.

### gossl

```bash
gossl validate -n naver.com -t naver.com/include/themecast/targetAndPanels.json
```

### curl

```bash
curl -vo /dev/null -H 'Range:bytes=0-1' --resolve 'naver.com:443:223.130.195.95' 'https://www.naver.com/include/themecast/targetAndPanels.json'
```

# License

gossl is licensed under the [MIT](https://github.com/ghdwlsgur/gossl/blob/master/LICENSE)
