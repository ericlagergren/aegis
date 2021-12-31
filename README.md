# aegis
<p align="center">
<a href="https://pkg.go.dev/github.com/ericlagergren/aegis"><img src="https://pkg.go.dev/badge/github.com/ericlagergren/aegis.svg" alt="Go Reference"></a>
</p>

<p align="center">AEGIS</p>

This module implements the AEGIS-128L and AEGIS-256 AEAD
algorithms.

See https://www.ietf.org/archive/id/draft-denis-aegis-aead-00.html
for more information.

IMPORTANT: this is a work in progress implementation of a draft
IETF specification. Do not use this library unless you understand
the implications.

## Installation

Each implementation can be installed using Go modules. For
example:

```bash
go get github.com/ericlagergren/aegis@latest
```

## Usage

The APIs conform to Go's `crypto/cipher` package. Note that the
following example is not a substitute for reading the package's
documentation.

```go
package main

import (
	"crypto/rand"

	"github.com/ericlagergren/aegis"
)

func main() {
	key := make([]byte, aegis.KeySize128L)
	if _, err := rand.Read(key); err != nil {
		// rand.Read failing is almost always catastrophic.
		panic(err)
	}

	nonce := make([]byte, aegis.NonceSize128L)
	if _, err := rand.Read(nonce); err != nil {
		// rand.Read failing is almost always catastrophic.
		panic(err)
	}

	aead, err := aegis.New(key)
	if err != nil {
		// New will only return an error if the key is an invalid
		// length.
		panic(err)
	}

	// Plaintext is encrypted and authenticated.
	plaintext := []byte("example plaintext")

	// Additional data is authenticated alongside the plaintext,
	// but not included in the ciphertext.
	additionalData := []byte("example additional authenticated data")

	// Encrypt and authenticate |plaintext| and authenticate
	// |additionalData|.
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)

	// Decrypt and authentiate |ciphertext| and authenticate
	// |additionalData|.
	plaintext, err = aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		// Authentication failed. Either the ciphertext or
		// additionalData (or both) were invalid for the 
		// (key, nonce) pair.
		[...]
	}
}
```

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in
an implementation, please e-mail me or create a GitHub issue.

### Disclaimer

You should only use cryptography libraries that have been
reviewed by cryptographers or cryptography engineers. While I am
a cryptography engineer, I'm not your cryptography engineer, and
I have not had this project reviewed by any other cryptographers.
