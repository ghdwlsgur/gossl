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

# Supported CAs

### `Leaf - Intermediate - Root`

- Sectigo RSA Domain Validation Secure Server CA
- GoGetSSL RSA DV CA
- GlobalSign GCC R3 DV TLS CA 2020

### `Leaf - Intermediate`

- Thawte RSA CA 2018
- AlphaSSL CA - SHA256 - G2
- GeoTrust RSA CA 2018
- RapidSSL RSA CA 2018

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

### unzip ➡️ echo ➡️ merge ➡️ split ➡️ zip ➡️ validate

- `unzip`: Unzip the compressed file.

- `echo`: Check the type of each certificate file and compare the md5 hash values. If the target file is an ecc private key, it is not supported. Also, if it is a private key, it can be converted to an rsa private key.

- `merge`: Combine the verified certificate files in the order of leaf, intermediate, and root.

- `split`: When there is an integrated certificate that combines root certificate, intermediate certificate, and domain certificate, the type of each block in the integrated certificate is verified and files are created for each block type.

- `zip`: Compress the merged certificate file and rsa private key into a zip file.

- `validate`: Check the certificate information hanging on the domain.

# How to use

### `unzip`

```bash
gossl unzip -n [fileName]
```

<div align="center">
<img src="https://user-images.githubusercontent.com/77400522/205485682-226ba402-692a-4304-88d3-8d87310ad90e.png">
<img src="https://user-images.githubusercontent.com/77400522/205485685-f165eef7-da8c-47d6-a733-ab6725437c8b.png">
</div>

### `echo`

```bash
gossl echo
```

<div align="center">
<img src="https://user-images.githubusercontent.com/77400522/205485947-d2ed8bb1-9b40-4add-aa18-ffb803e96db7.png">
<img src="https://user-images.githubusercontent.com/77400522/205485948-874dd6d0-f114-4309-983d-f1c38750a5ea.png">
</div>

### `merge`

```bash
gossl merge -n [fileName]
```

<div align="center">
<img src="https://user-images.githubusercontent.com/77400522/205485834-4eb17caf-3e34-47ff-a73f-1364a1b67049.png">
<img src="https://user-images.githubusercontent.com/77400522/205485835-766ee3c3-727b-489a-aefe-2ca81ae53cc3.png">
</div>

### `split`

```bash
gossl split # make file
gossl split show # not make file
```

<div align="center">
<img src="https://user-images.githubusercontent.com/77400522/205486021-b1677395-ec89-487b-ae60-f7f5bdfd998e.png">
<img src="https://user-images.githubusercontent.com/77400522/205486020-7c674c92-7ef6-441e-bbad-f0c6a8459e68.png">
</div>

### `zip`

```bash
gossl zip -n [fileName]
```

<div align="center">
<img src="https://user-images.githubusercontent.com/77400522/205486258-550e58ba-94b8-42a1-8f4d-421e46e8aa7b.png">
<img src="https://user-images.githubusercontent.com/77400522/205486262-4331d819-17ea-4a22-aaef-3c093543859a.png">
</div>

### `validate`

```bash
gossl validate -n [domain]
```

<div align="center">
<img src="https://user-images.githubusercontent.com/77400522/205486339-a6d35942-a160-4553-8976-38a072f04436.png">
</div>

# License

gossl is licensed under the [MIT](https://github.com/ghdwlsgur/gossl/blob/master/LICENSE)
