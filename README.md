<div align="center">

<br>
<br>

<img width="50%" alt="gossl-logo" src="https://user-images.githubusercontent.com/77400522/202766468-72b9c4ac-2191-4c8d-945e-97d96a75c3aa.png">

![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/ghdwlsgur/gossl?color=success&label=version&sort=semver)
[![ci](https://github.com/ghdwlsgur/gossl/actions/workflows/ci.yml/badge.svg)](https://github.com/ghdwlsgur/gossl/actions/workflows/ci.yml)

</div>

# gossl

Your CA sent you a zip. Inside are `cert.pem`, `1.crt` and `ca-bundle.crt`, and
nginx wants them concatenated leaf first. Which one is the leaf?

`openssl` can answer that, but only if you already know which question to ask.
gossl starts from not knowing.

```bash
$ gossl split show bundle.pem
✅ bundle.pem
	 ➕ Leaf Certificate [in 1 block]
	 ➕ Intermediate Certificate [in 1 block]
	 ➕ Root Certificate [in 1 block]

Leaf:[Issuer CN] Intermediate:[Subject CN] Matched
Intermediate:[Issuer CN] Root:[Subject CN] Matched

$ gossl split bundle.pem
✅ bundle.pem
	 ➕ Leaf Certificate [in 1 block]
	 ➕ Intermediate Certificate [in 1 block]
	 ➕ Root Certificate [in 1 block]

Created Files
📄 gossl_leaf_1.crt created successfully
📄 gossl_intermediate_1.crt created successfully
📄 gossl_root_1.crt created successfully
```

## Why not just openssl

**Splitting a bundle into leaf, intermediate and root.** openssl has no command
for this, because telling the three apart means reading `IsCA` and checking
whether a certificate signed itself. You end up doing it by hand:

```bash
# before
awk '/BEGIN CERT/{n++} {print > ("cert" n ".pem")}' bundle.pem
for f in cert*.pem; do
  echo "== $f"
  openssl x509 -noout -subject -issuer -ext basicConstraints -in "$f"
done
# then work out which is which, and rename them yourself

# after
gossl split bundle.pem
```

**Checking what every CDN edge actually serves.** The certificate on one edge is
not always the certificate on the next, and finding out means pinning the IP
while keeping SNI on the hostname:

```bash
# before
for ip in $(dig +short example.com); do
  echo "== $ip"
  openssl s_client -connect "$ip:443" -servername example.com </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates
done

# after
gossl validate example.com
```

**Checking that a certificate and a key belong together.**

```bash
# before
openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa  -noout -modulus -in server.key | openssl md5
# compare the two by eye

# after
gossl inspect server.crt
gossl inspect server.key
```

Certificates may use RSA, ECDSA or Ed25519 keys. Private keys are read in PKCS#1
(`RSA PRIVATE KEY`), PKCS#8 (`PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`) form, plus
legacy RFC 1423 encrypted PEM.

[Korean Document](https://ghdwlsgur.github.io/docs/OpenSource/gossl)

## Two ways to run it

Every file-taking command works both ways. Name the file and gossl does what you
said. Leave it out and gossl lists what is in the current directory and asks.

```bash
gossl inspect                 # lists the certificates here, asks which one
gossl inspect server.crt      # no prompt, so it runs in a pipeline
```

Nothing prompts when the file is given, which means gossl can run under CI,
cron or a deploy script:

```bash
gossl split show bundle.pem                       # report the chain, write nothing
gossl merge leaf.pem chain.pem -n bundle          # bundle.pem
GOSSL_PASSWORD=... gossl unlock server.key        # decrypt without a terminal
```

## Installation

### homebrew

```bash
# [install]
brew install --cask ghdwlsgur/gossl/gossl

# [upgrade]
brew upgrade --cask gossl
```

gossl ships as a Homebrew cask, not a formula, because a formula is meant to
build from source and gossl ships prebuilt binaries. macOS and Linux, Intel and
ARM are all covered. If you installed the old formula, `brew upgrade` moves you
across on its own.

### [Download](https://github.com/ghdwlsgur/gossl/releases)

### docker

gossl reads certificate files from the current directory, so mount the directory
you want to work in at `/work`.

```bash
docker build -t gossl .
docker run --rm -v "$PWD:/work" gossl split bundle.pem
docker run --rm -it -v "$PWD:/work" gossl inspect     # -it for the prompt
docker run --rm gossl check example.com
```

## Commands

### `inspect`

Shows what a certificate or key file actually is: whether it is a leaf, chain or
root certificate, its `Md5 Hash`, `expiration date`, `Subject`, `Issuer` and
`Verify Host`, and for a leaf certificate its `Subject Alternative Name`.

For RSA keys the `Md5 Hash` matches `openssl x509 -noout -modulus | openssl md5`,
so a certificate and a private key belong together when the two hashes are equal.
ECDSA and Ed25519 keys are hashed from their PKIX public key, which openssl has no
direct equivalent for, but the same cert/key comparison still holds.

```bash
gossl inspect                      # ask which file
gossl inspect server.crt           # no prompt
gossl inspect legacy.crt --convert # also convert CRT to PEM, or PRIVATE KEY to RSA PRIVATE KEY
```

`echo` is kept as an alias, so older scripts keep working.

### `split`

Splits a unified certificate into `gossl_leaf_1.crt`, `gossl_intermediate_1.crt`
and `gossl_root_1.crt`, naming each file after what it turned out to be. `show`
reports the chain and whether each link matches, without writing anything.

```bash
gossl split                   # ask which file, then write
gossl split bundle.pem        # write
gossl split show              # ask which file, report only
gossl split show bundle.pem   # report only
```

### `merge`

Combines certificate files into one, in leaf, intermediate, root order. Takes 2
to 4 files. The output defaults to `gossl_merge_output.pem`. A private key is
rejected unless `-f` is given, in which case it is appended after the
certificates.

```bash
gossl merge                                  # ask which files
gossl merge leaf.pem chain.pem               # gossl_merge_output.pem
gossl merge leaf.pem chain.pem -n bundle     # bundle.pem
gossl merge leaf.pem server.key -f           # allow a private key in the output
```

### `unlock`

Decrypts a password protected private key in place. The replacement is atomic:
the decrypted key is written to a temporary file in the same directory and then
renamed over the original, so a failure never leaves you without the key.

```bash
gossl unlock                                      # ask which file, then ask for the password
gossl unlock server.key --password-file pw.txt
GOSSL_PASSWORD=... gossl unlock server.key
```

There is deliberately no `--password` flag. A password on the command line is
visible to every other process on the host through `ps`.

### `validate`

Contacts every IPv4 address behind the domain directly, with SNI set to the
domain name, so you can compare what each CDN edge actually serves. Without a
CDN this is just the origin.

```bash
gossl validate [domain]
```

### `check`

Retrieves the certificate applied to the domain.

```bash
gossl check [domain]
```

### `download`

Downloads one of the bundled root certificates into the current directory. The
bundle is generated from [CCADB](https://www.ccadb.org/resources) and refreshed
monthly by CI, so it does not go stale the way a hand maintained list does.

```bash
gossl download
```

### `zip` / `unzip`

Compresses the certificate files here into one archive, and unpacks it again.

```bash
gossl zip -n [fileName]
gossl unzip -n [fileName]
```

## Chain of trust

![chain of trust](https://user-images.githubusercontent.com/77400522/202842089-542edbb9-4c0a-44cb-93a9-0f3e61dd5ecf.png)

A chain of trust is what makes `split` and `merge` meaningful. Each certificate
is vouched for by the one above it: the leaf is signed by an intermediate, the
intermediate by a root, and the root signs itself. A web server has to present
that chain in order, from leaf upward, or clients cannot walk it back to a root
they already trust.

That is why the order matters, why a bundle with a missing intermediate fails on
some clients and not others, and why `gossl split show` reports each link as
matched or not.

See [Chain of trust](https://en.wikipedia.org/wiki/Chain_of_trust) for the longer
version.

## License

gossl is licensed under the [MIT](https://github.com/ghdwlsgur/gossl/blob/main/LICENSE)
