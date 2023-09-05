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

This is an interactive CLI tool that helps to check and process the information of certificate and private key files, making it easy to apply the certificate to a web server.

[Korean Document](https://ghdwlsgur.github.io/docs/OpenSource/gossl)

# Chain of trust

![스크린샷 2022-11-19 오후 5 26 49](https://user-images.githubusercontent.com/77400522/202842089-542edbb9-4c0a-44cb-93a9-0f3e61dd5ecf.png)

- https://en.wikipedia.org/wiki/Chain_of_trust

A chain of trust is designed to allow multiple users to create and use software on the system, which would be more difficult if all the keys were stored directly in hardware. It starts with hardware that will only boot from software that is digitally signed. The signing authority will only sign boot programs that enforce security, such as only running programs that are themselves signed, or only allowing signed code to have access to certain features of the machine. This process may continue for several layers.

This process results in a chain of trust. The final software can be trusted to have certain properties, because if it had been illegally modified its signature would be invalid, and the previous software would not have executed it. The previous software can be trusted, because it, in turn, would not have been loaded if its signature had been invalid. The trustworthiness of each layer is guaranteed by the one before, back to the trust anchor.

It would be possible to have the hardware check the suitability (signature) for every single piece of software. However, this would not produce the flexibility that a "chain" provides. In a chain, any given link can be replaced with a different version to provide different properties, without having to go all the way back to the trust anchor. This use of multiple layers is an application of a general technique to improve scalability, and is analogous to the use of multiple certificates in a certificate chain.

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

# How to use

### `cat`

The tool displays a list of files with extensions ending in `pem, crt, ca, csr, cer, and key` in the current directory as options. If a single certificate file is selected, it indicates whether it is a chain certificate, root certificate, or domain certificate, and shows the `Md5 Hash` value, `expiration date`, `Subject` and `Issuer` information, and `Verify Host`. If the certificate is a domain certificate, it also provides additional information on `Subject Alternative Name`.

The option is provided to convert a `crt` file to `pem` format.

```bash
gossl cat
```

### `merge`

When you select each individual file of domain certificate, chain certificate, and root certificate, it combines them into one certificate file in the order of domain certificate, chain certificate, and root certificate.

```bash
gossl merge -n [fileName]
```

### `split`

Shows the order in which the domain certificate, chain certificate, and root certificate are composed into a single certificate file, or splits the file into separate files named according to the type of certificate, such as `gossl_internetiate_1.crt`, `gossl_leaf_1.crt`, and `gossl_root_1.crt`, so that the type of each certificate can be identified.

```bash
gossl split # make file
gossl split show # not make file
```

### `unlock`

When a private key is password-protected, it prompts for the password and replaces the original key with an unencrypted one.

```bash
gossl unlock
```

### `zip`

Compresses each file into a single archive.

```bash
gossl zip -n [fileName]
```

### `unzip`

Decompresses the compressed file.

```bash
gossl unzip -n [fileName]
```

### `validate`

If the domain uses a CDN, it retrieves the domain certificate information applied to each edge device. If not, it retrieves the domain certificate information applied to the origin server.

```bash
gossl validate -n [domain]
```

### `check`

It retrieves the certificate information applied to the domain.

```bash
gossl check [domain]
```

### `download`

If you select one of the root certificates provided by gossl, it will be downloaded to the current directory.

```bash
gossl download
```

# License

gossl is licensed under the [MIT](https://github.com/ghdwlsgur/gossl/blob/master/LICENSE)
