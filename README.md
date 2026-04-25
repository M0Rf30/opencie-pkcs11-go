# opencie-pkcs11-go

Go bindings for the [opencie-pkcs11](https://github.com/M0Rf30/opencie-pkcs11) library, providing PKCS#11 interface and CIE-specific extensions for Italian Electronic Identity Cards.

## Installation

```bash
go get github.com/M0Rf30/opencie-pkcs11-go
```

### Build Requirements

- **libopencie-pkcs11** must be installed on your system
  - See [opencie-pkcs11 releases](https://github.com/M0Rf30/opencie-pkcs11/releases) for pre-built binaries
  - Or build from [source](https://github.com/M0Rf30/opencie-pkcs11)
- **CGO_ENABLED=1** (required for cgo)
- A C compiler (gcc, clang, or MinGW-w64 on Windows)

On most Linux systems with the library installed in standard paths, the bindings should work out of the box. If the library is installed in a custom location, set:

```bash
export CGO_CFLAGS="-I/path/to/include"
export CGO_LDFLAGS="-L/path/to/lib -lopencie-pkcs11"
```

## Packages

This module provides two packages:

### 1. `pkcs11` - Standard PKCS#11 Interface

Wraps the standard PKCS#11 cryptographic token interface (57 of 69 functions supported). Provides access to:
- Session management
- Object handling (keys, certificates)
- Cryptographic operations (sign, verify, encrypt, decrypt, digest)
- Key generation
- Random number generation

### 2. `cie` - CIE-Specific Extensions

Wraps CIE card enrolment, PIN management, signing, and verification functions specific to Italian Electronic Identity Cards.

## Usage Examples

### PKCS#11: Basic Token Operations

```go
package main

import (
    "fmt"
    "log"

    "github.com/M0Rf30/opencie-pkcs11-go/pkcs11"
)

func main() {
    if err := pkcs11.Initialize(); err != nil {
        log.Fatal(err)
    }
    defer pkcs11.Finalize()

    info, err := pkcs11.GetInfo()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Library: %s\n", info.LibraryDescription)

    slots, err := pkcs11.GetSlotList(true)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Found %d slot(s) with tokens\n", len(slots))

    if len(slots) == 0 {
        return
    }

    session, err := pkcs11.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
    if err != nil {
        log.Fatal(err)
    }
    defer pkcs11.CloseSession(session)

    if err := pkcs11.Login(session, pkcs11.CKU_USER, "12345678"); err != nil {
        log.Fatal(err)
    }
    defer pkcs11.Logout(session)

    fmt.Println("Logged in successfully")
}
```

### CIE: Enrolment and PIN Management

```go
package main

import (
    "fmt"
    "log"

    "github.com/M0Rf30/opencie-pkcs11-go/cie"
)

func main() {
    pan := "1234567890123456"
    pin := "12345678"

    if cie.IsEnabled(pan) {
        fmt.Println("Card is already enrolled")
        return
    }

    var attempts int
    if err := cie.Enable(pan, pin, &attempts, nil, nil); err != nil {
        log.Fatalf("Enrolment failed: %v (attempts left: %d)", err, attempts)
    }
    fmt.Println("Card enrolled successfully")

    newPIN := "87654321"
    if err := cie.ChangePin(pin, newPIN, &attempts, nil); err != nil {
        log.Fatalf("PIN change failed: %v (attempts left: %d)", err, attempts)
    }
    fmt.Println("PIN changed successfully")
}
```

### CIE: PDF Signing and Verification

```go
package main

import (
    "log"
    "os"

    "github.com/M0Rf30/opencie-pkcs11-go/cie"
)

func main() {
    pan := "1234567890123456"
    pin := "12345678"
    inFile := "document.pdf"
    outFile := "document_signed.pdf"

    var imageData []byte
    if data, err := os.ReadFile("signature.png"); err == nil {
        imageData = data
    }

    err := cie.Sign(
        inFile,
        "PDF",
        pin,
        pan,
        0,
        100, 100,
        200, 50,
        imageData,
        outFile,
        nil,
        nil,
    )
    if err != nil {
        log.Fatalf("Signing failed: %v", err)
    }
    log.Println("Document signed:", outFile)

    sigCount, err := cie.Verify(outFile, "", 0, "")
    if err != nil {
        log.Fatalf("Verification failed: %v", err)
    }
    log.Printf("Found %d valid signature(s)\n", sigCount)

    for i := 0; i < sigCount; i++ {
        info, err := cie.GetVerifyInfo(i)
        if err != nil {
            log.Fatal(err)
        }
        log.Printf("Signer #%d: %s %s (%s)\n", i+1, info.Name, info.Surname, info.CN)
        log.Printf("  Signed at: %s\n", info.SigningTime)
        log.Printf("  Valid: %v\n", info.IsSignValid)
    }
}
```

### CIE: Reader Management

```go
package main

import (
    "fmt"

    "github.com/M0Rf30/opencie-pkcs11-go/cie"
)

func main() {
    n := cie.ReaderCount()
    fmt.Printf("Readers attached: %d\n", n)

    if n > 0 {
        if name, err := cie.ReaderName(); err == nil {
            fmt.Printf("First reader: %s\n", name)
        }
    }

    fmt.Println("Waiting for reader change...")
    n = cie.ReaderWatch(n)
    fmt.Printf("Reader count is now: %d\n", n)
}
```

### CIE: DigestInfo Encoding

```go
package main

import (
    "crypto/sha256"
    "fmt"
    "log"

    "github.com/M0Rf30/opencie-pkcs11-go/cie"
)

func main() {
    msg := []byte("hello world")
    hash := sha256.Sum256(msg)

    const algidSHA256 = 4
    di, err := cie.MakeDigestInfo(algidSHA256, hash[:])
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("DigestInfo (%d bytes): %x\n", len(di), di)
}
```

## Limitations

- **Callbacks**: The `cie` package does not currently support passing Go callbacks through cgo. Progress and completion callbacks must be passed as `nil`. A future version may implement a cookie-based mechanism.
- **Thread Safety**: The underlying C library uses locking; Go code should still avoid concurrent calls to the same session or context from multiple goroutines without external synchronization.
- **Memory Management**: The bindings handle C memory allocation/deallocation internally. Do not manually free pointers returned by the C library.

## Platform Support

- **Linux** (x86_64, aarch64)
- **Windows** (x86_64, via MinGW-w64 cross-compilation)
- **macOS** (arm64)
- **Android** (arm64, experimental)

## Changelog

### Unreleased — sync with libopencie-pkcs11 main

- **Breaking**: `cie.Sign` now takes `imageData []byte` instead of an image path string, matching the upstream 14-argument `cie_sign` signature in `cie_ext.h`.
- **Breaking**: Removed the `sign` package. The corresponding `cie_sign_*` C++ API was removed from libopencie-pkcs11; the public signing flow is now exposed through `cie.Sign`.
- **Fix**: `cie.Verify` and `cie.GetSignCount` no longer rely on a `rv < 0` check on an unsigned `CK_RV`. Returns above `0x1000` are now correctly reported as `RV` errors.
- Added `cie.ReaderCount`, `cie.ReaderWatch`, `cie.ReaderName` wrappers.
- Added `cie.MakeDigestInfo` wrapper around `make_digest_info`.
- Added `cie.GetVerifyInfo` returning a typed `VerifyInfo` struct.
- Added GitHub Actions CI building libopencie-pkcs11 from source and running `go vet`/`go build`/`gofmt` against the bindings.

## License

This Go module is released under the same license as the underlying library (GPL-2.0-or-later).
See the [opencie-pkcs11 LICENSE](https://github.com/M0Rf30/opencie-pkcs11/blob/main/LICENSE.md) for details.

## Links

- **Upstream C library**: [github.com/M0Rf30/opencie-pkcs11](https://github.com/M0Rf30/opencie-pkcs11)
- **Issues**: [github.com/M0Rf30/opencie-pkcs11-go/issues](https://github.com/M0Rf30/opencie-pkcs11-go/issues)
- **CIE Official Site**: [www.cartaidentita.interno.gov.it](https://www.cartaidentita.interno.gov.it/)

---

**Maintained by**: Gianluca Boiano ([@M0Rf30](https://github.com/M0Rf30))
