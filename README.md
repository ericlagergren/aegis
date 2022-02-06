# aegis

[![Go Reference](https://pkg.go.dev/badge/github.com/ericlagergren/aegis.svg)](https://pkg.go.dev/github.com/ericlagergren/aegis)

This module implements the AEGIS-128L and AEGIS-256 AEAD
algorithms.

See https://competitions.cr.yp.to/round3/aegisv11.pdf or 
https://www.ietf.org/archive/id/draft-denis-aegis-aead-00.html
for more information.

## Installation

```bash
go get github.com/ericlagergren/aegis@latest
```

## Usage

The APIs conform to Go's `crypto/cipher` package. Note that the
following example is not a substitute for reading the package
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

## Performance

The x86-64 and ARMv8 assembly implementations run at 0.3 and 0.4
cycles per byte, respectively. The x86-64 implementation requires
SSE4.1 and AES instructions. The ARMv8 implementation requires
NEON and AES instructions.

The default pure Go implementation will be selected if the CPU
does not support either assembly implementation. (This 
implementation can also be selected with the `purego` build tag.) 
It is much slower at around 5.6 cycles per byte.

Note also that the pure Go implementation uses S-boxes and leaks
cache timing information. See golang.org/issues/13795 for more
information.

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in
an implementation, please e-mail me or create a GitHub issue.

### Disclaimer

You should only use cryptography libraries that have been
reviewed by cryptographers or cryptography engineers. While I am
a cryptography engineer, I'm not your cryptography engineer, and
I have not had this project reviewed by any other cryptographers.
