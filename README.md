# opencie-pkcs11-go

Go bindings for the [opencie-pkcs11](https://github.com/M0Rf30/opencie-pkcs11) library, providing PKCS#11 interface and CIE-specific extensions for Italian Electronic Identity Cards.

## Installation

```bash
go get github.com/M0Rf30/opencie-pkcs11-go
```

### Build Requirements

- **libopencie-pkcs11 1.3.0 or newer** must be installed on your system
  - See [opencie-pkcs11 releases](https://github.com/M0Rf30/opencie-pkcs11/releases) for pre-built binaries
  - Or build from [source](https://github.com/M0Rf30/opencie-pkcs11)
  - Earlier versions do not export `cie_read_dgs_can`, `cie_get_certificate`, `cie_free`, `cie_timestamp` or `cie_classify_sw`/`cie_last_error`, so cgo will fail to resolve them; `IsEnabled` and the certificate lookup also behave differently before 1.3.0 (see the changelog)
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

Wraps the standard PKCS#11 cryptographic token interface (37 of the library's 69 exported `C_*` functions). Provides access to:
- Session management
- Object handling (keys, certificates)
- Cryptographic operations (sign, verify, encrypt, decrypt, digest)
- Key generation
- Random number generation

### 2. `cie` - CIE-Specific Extensions

Wraps CIE card enrolment, PIN management, signing, verification, timestamping, certificate retrieval and chip data-group reading (DG1/DG2) for Italian Electronic Identity Cards.

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
        0.10, 0.10,
        0.50, 0.12,
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
    log.Printf("Found %d signature(s)\n", sigCount)

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

### CIE: Progress Callbacks

```go
err := cie.Enable(pan, pin, &attempts,
    func(progress int, message string) error {
        fmt.Printf("%3d%% %s\n", progress, message)
        return nil
    },
    func(pan, name, serial string) error {
        fmt.Printf("paired %s (%s), serial %s\n", pan, name, serial)
        return nil
    },
)
```

The callbacks run on the calling goroutine while the library is mid-operation.
`nil` is always safe: the bindings hand the C library no-op trampolines, because
libopencie-pkcs11 calls its callbacks unconditionally.

### CIE: Reading DG1/DG2 with the CAN

```go
package main

import (
    "errors"
    "fmt"
    "log"

    "github.com/M0Rf30/opencie-pkcs11-go/cie"
)

func main() {
    // PACE with the 6-digit CAN printed on the card; no PIN is used.
    dg, err := cie.ReadDGSCan("123456")
    switch {
    case err == nil:
        fmt.Printf("DG1: %d bytes, photo (PNG): %d bytes\n", len(dg.MRZ), len(dg.Photo))
    case errors.Is(err, cie.ErrCANRejected):
        // CKR_PIN_INCORRECT + CIE_ERR_WRONG_CAN. Never retried
        // automatically with the same CAN: ask the user again.
        log.Fatal("wrong CAN")
    case errors.Is(err, cie.ErrExtendedAPDUNotSupported):
        // Short-APDU-only reader (e.g. ACS ACR122U): use the PIN fallback
        // or another reader.
        dg, err = cie.ReadDGS("12345678")
        if err != nil {
            log.Fatal(err)
        }
    case errors.Is(err, cie.ErrPACENotSupported):
        log.Fatal("this chip has no PACE")
    default:
        log.Fatal(err)
    }
    _ = dg
}
```

`ReadDGSCan` and `ReadDGS` return a `*cie.CardError` carrying the `RV`, the
`cie_last_error` kind and the raw status word (the OS thread is locked around
the call and the lookup for you).

### CIE: Certificate and Timestamp

```go
der, err := cie.GetCertificate(pan) // DER X.509; the C buffer is released with cie_free
if err != nil {
    log.Fatal(err)
}
fmt.Printf("certificate: %d bytes\n", len(der))

// RFC 3161 timestamp of a file: no card needed.
err = cie.Timestamp("document.pdf", "https://tsa.example/tsr", "", "", "document.pdf.tst", nil)
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
        // The most useful reader: one holding a card, else an empty
        // contactless slot, else any other empty slot.
        if name, err := cie.ReaderName(); err == nil {
            fmt.Printf("Reader: %s\n", name)
        }
    }

    fmt.Println("Waiting for reader change...")
    n = cie.ReaderWatch(n) // -1 if PC/SC is unavailable
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

    di, err := cie.MakeDigestInfo(cie.NIDSHA256, hash[:])
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("DigestInfo (%d bytes): %x\n", len(di), di)
}
```

## Limitations

- **Callbacks**: `cie` progress/completion callbacks are real Go functions (see "Progress Callbacks"). The C library gives its callbacks no user-data pointer, so calls that take callbacks (`Enable`, `ChangePin`, `UnblockPin`, `Sign`, `Timestamp`) are serialised per process. A panic in a callback is re-raised in the calling goroutine once the C call returns. `libopencie-pkcs11` 1.3.0 ignores the callbacks' return value.
- **Thread Safety**: The underlying C library uses locking; Go code should still avoid concurrent calls to the same session or context from multiple goroutines without external synchronization. `Verify`, `GetSignCount` and `GetVerifyInfo` share one global result in the library and are serialised by the bindings. `cie.LastError` is thread-local: lock the OS thread around a card call and `LastError` (`ReadDGS`/`ReadDGSCan` do it for you).
- **Memory Management**: The bindings handle C memory allocation/deallocation internally. `GetCertificate` copies the certificate out of the buffer the library allocated and releases that buffer with `cie_free`; do not free pointers returned by the C library yourself.
- **`MakeDigestInfo`**: implemented in Go. The Linux release binaries of libopencie-pkcs11 (including 1.3.0) do not export `make_digest_info` although the header lists it, so binding it would break linking. The output is identical to the C function's.
- **Not bound**: `cie_set_data_dir` (Android only) and the JNI/NFC bridge.

## Testing

The unit tests need no card and no reader; they link against libopencie-pkcs11 1.3.0 or newer and exercise struct layouts, return-code classification, the library's pure functions and its argument validation:

```bash
export CGO_CFLAGS="-I/path/to/opencie-pkcs11/shared/src -I/path/to/opencie-pkcs11/include"
# only if the library is not in a standard location:
export CGO_LDFLAGS="-L/path/to/lib"
export LD_LIBRARY_PATH=/path/to/lib
gofmt -l .
go vet ./...
go test ./...
```

## Platform Support

- **Linux** (x86_64, aarch64)
- **Windows** (x86_64, via MinGW-w64 cross-compilation)
- **macOS** (arm64)
- **Android** (arm64, experimental)

## Changelog

### v0.2.0 — libopencie-pkcs11 1.3.0

- Require **libopencie-pkcs11 1.3.0 or newer**.
- Added `cie.ReadDGSCan` (`cie_read_dgs_can`, PACE with the 6-digit CAN) and `cie.ReadDGS` (`cie_read_dgs`, PIN-based fallback), returning `*cie.DataGroups`. Failures are `*cie.CardError` values carrying the `RV`, the `cie_last_error` kind and the status word; `errors.Is` matches `cie.ErrCANRejected` (wrong CAN: `CKR_PIN_INCORRECT` + `ErrWrongCan`), `cie.ErrExtendedAPDUNotSupported` (`CKR_DEVICE_ERROR` + `ErrInsNotSupported`) and `cie.ErrPACENotSupported` (`CKR_FUNCTION_NOT_SUPPORTED` + `ErrUnsupportedCard`).
- Added `cie.ErrWrongCan` (11) and `cie.ErrUnsupportedCard` (10) error kinds, `ErrorKind.String`.
- Added `cie.GetCertificate` (`cie_get_certificate`, released with `cie_free`) and `cie.Timestamp` (`cie_timestamp`).
- **Fix**: `cie.Verify` follows the 1.3.0 contract: the result is a signature count only if it equals `cie_get_sign_count()` and is not an error code (`CIE_SIGN_ERROR_*` from `0x84000000`, or a negative status cast to `CK_RV`); previously any value below `0x1000` counted as a number of signatures. The `CIE_SIGN_ERROR_*` codes are exported as `cie.SignErr*`.
- **Fix**: progress/completion callbacks were always passed as `NULL`, but the library calls them unconditionally, so `Enable`, `ChangePin`, `UnblockPin`, `Sign` and the new `Timestamp` crashed the process. The bindings now always pass C trampolines that forward to the optional Go callbacks, which are now functional.
- **Fix**: `cie.ReaderName` returned only the first character of the reader name (`cie_reader_name` returns 1/0, not the length) and its documentation described "the first reader" instead of the best match.
- **Fix**: `cie.IsEnabled` documentation: since 1.3.0 `cie_is_enabled` returns 1 only if a cache exists; a card that is merely present is not enabled.
- **Fix**: `cie.Sign` documentation: `x`, `y`, `w`, `h` are fractions (0.0-1.0) of the crop box, not PDF points; the README example was wrong.
- **Fix**: the README `MakeDigestInfo` example used algid `4`, which is not an OpenSSL NID (SHA-256 is `672`). Added `cie.NIDSHA1/256/384/512`; unsupported algorithms and wrong digest lengths now return `ErrUnsupportedDigestAlgorithm`/`ErrInvalidDigestLength`. `MakeDigestInfo` is implemented in Go because the Linux release binaries do not export `make_digest_info`.
- **Fix** (`pkcs11`): structures were compiled with `#pragma pack(1)` on every platform, but the library uses natural alignment outside Windows. `CK_INFO` was 76 bytes instead of 88, so `GetInfo` overran its buffer and read `LibraryDescription`/`LibraryVersion` from the wrong offsets, and `Info.Flags` was always 0. Packing is now Windows-only and a compile-time assertion guards the layout.
- **Fix** (`pkcs11`): fixed-size, blank-padded info strings (manufacturer, label, model, serial, ...) were read as NUL-terminated C strings, over-reading the field and keeping the padding; they are now trimmed.
- **Fix** (`pkcs11`): attribute templates and mechanism parameters were Go memory holding Go pointers handed to C, which panics under the default `cgocheck` (`FindObjectsInit`, `GetAttributeValue`, `CreateObject`, `SetAttributeValue`, `GenerateKey[Pair]`, `*Init`). They are now built in C memory.
- **Fix** (`pkcs11`): empty slices and empty templates no longer panic (`&s[0]`); `FindObjects`/`GenerateRandom` reject negative counts.
- Added unit tests (no card needed) for both packages. The README claimed 57 of 69 `C_*` functions; the `pkcs11` package binds 37.

### v0.1.1

- Require **libopencie-pkcs11 1.0.15 or newer**. Since 1.0.15, `cie_is_enabled`
  also recognizes cards paired only through the official IPZS CIE ID app
  (present on the reader, no local cache entry), and certificate lookups
  fall back to reading directly from the card when the cache has none.
  `IsEnabled` doc comment updated to describe this behaviour.

### Unreleased — sync with libopencie-pkcs11 main

- **Breaking**: `cie.Sign` now takes `imageData []byte` instead of an image path string, matching the upstream 14-argument `cie_sign` signature in `cie_ext.h`.
- **Breaking**: Removed the `sign` package. The corresponding `cie_sign_*` C++ API was removed from libopencie-pkcs11; the public signing flow is now exposed through `cie.Sign`.
- **Fix**: `cie.Verify` and `cie.GetSignCount` no longer rely on a `rv < 0` check on an unsigned `CK_RV`. Returns above `0x1000` are now correctly reported as `RV` errors.
- Added `cie.ReaderCount`, `cie.ReaderWatch`, `cie.ReaderName` wrappers.
- Added `cie.MakeDigestInfo` wrapper around `make_digest_info`.
- Added `cie.GetVerifyInfo` returning a typed `VerifyInfo` struct.
- Added GitHub Actions CI building libopencie-pkcs11 from source and running `go vet`/`go build`/`gofmt` against the bindings.

## License

This Go module (the bindings in this repository) is licensed under the
**Mozilla Public License 2.0** (MPL-2.0). See [`LICENSE`](LICENSE).

The underlying C library [`libopencie-pkcs11`](https://github.com/M0Rf30/opencie-pkcs11)
is distributed under the **GNU Lesser General Public License v3.0** (LGPL-3.0);
see its [`LICENSE.md`](https://github.com/M0Rf30/opencie-pkcs11/blob/main/LICENSE.md).
Any binary that links these bindings against `libopencie-pkcs11` constitutes a
combined work and must additionally comply with the terms of LGPL-3.0.

## Links

- **Upstream C library**: [github.com/M0Rf30/opencie-pkcs11](https://github.com/M0Rf30/opencie-pkcs11)
- **Issues**: [github.com/M0Rf30/opencie-pkcs11-go/issues](https://github.com/M0Rf30/opencie-pkcs11-go/issues)
- **CIE Official Site**: [www.cartaidentita.interno.gov.it](https://www.cartaidentita.interno.gov.it/)

---

**Maintained by**: Gianluca Boiano ([@M0Rf30](https://github.com/M0Rf30))
