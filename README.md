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
    // Initialize the library
    if err := pkcs11.Initialize(); err != nil {
        log.Fatal(err)
    }
    defer pkcs11.Finalize()

    // Get library info
    info, err := pkcs11.GetInfo()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Library: %s\n", info.LibraryDescription)

    // List slots with tokens
    slots, err := pkcs11.GetSlotList(true)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Found %d slot(s) with tokens\n", len(slots))

    if len(slots) == 0 {
        return
    }

    // Open a session on the first slot
    session, err := pkcs11.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
    if err != nil {
        log.Fatal(err)
    }
    defer pkcs11.CloseSession(session)

    // Login with PIN
    if err := pkcs11.Login(session, pkcs11.CKU_USER, "12345678"); err != nil {
        log.Fatal(err)
    }
    defer pkcs11.Logout(session)

    fmt.Println("Logged in successfully")

    // Find certificate objects
    if err := pkcs11.FindObjectsInit(session, []pkcs11.Attribute{
        {Type: 0x00000000, Value: []byte{0x01}}, // CKA_CLASS = CKO_CERTIFICATE
    }); err != nil {
        log.Fatal(err)
    }
    defer pkcs11.FindObjectsFinal(session)

    objects, err := pkcs11.FindObjects(session, 10)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Found %d certificate(s)\n", len(objects))
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
    pan := "1234567890123456" // PAN from your CIE card
    pin := "12345678"         // 8-digit PIN

    // Check if card is already enrolled
    if cie.IsEnabled(pan) {
        fmt.Println("Card is already enrolled")
        return
    }

    // Enroll the card
    // Note: Callbacks are not fully supported; pass nil
    var attempts int
    if err := cie.Enable(pan, pin, &attempts, nil, nil); err != nil {
        log.Fatalf("Enrolment failed: %v (attempts left: %d)", err, attempts)
    }

    fmt.Println("Card enrolled successfully")

    // Change PIN
    newPIN := "87654321"
    if err := cie.ChangePin(pin, newPIN, &attempts, nil); err != nil {
        log.Fatalf("PIN change failed: %v (attempts left: %d)", err, attempts)
    }

    fmt.Println("PIN changed successfully")
}
```

### CIE: PDF Signing

```go
package main

import (
    "log"

    "github.com/M0Rf30/opencie-pkcs11-go/cie"
)

func main() {
    pan := "1234567890123456"
    pin := "12345678"
    inFile := "document.pdf"
    outFile := "document_signed.pdf"

    // Sign a PDF with visible signature widget
    err := cie.Sign(
        inFile,
        "PDF",           // signature type
        pin,
        pan,
        0,               // page 0 (first page)
        100, 100,        // x, y position in points
        200, 50,         // width, height in points
        "",              // no signature image
        outFile,
        nil,             // progress callback (not supported)
        nil,             // completed callback (not supported)
    )
    if err != nil {
        log.Fatalf("Signing failed: %v", err)
    }

    log.Println("Document signed successfully:", outFile)

    // Verify the signed document
    sigCount, err := cie.Verify(outFile, "", 0, "")
    if err != nil {
        log.Fatalf("Verification failed: %v", err)
    }

    log.Printf("Found %d valid signature(s)\n", sigCount)

    // Get info about the first signature
    if sigCount > 0 {
        info, err := cie.GetVerifyInfo(0)
        if err != nil {
            log.Fatal(err)
        }
        log.Printf("Signer: %s %s\n", info.Name, info.Surname)
        log.Printf("Signed at: %s\n", info.SigningTime)
        log.Printf("Valid: %v\n", info.IsSignValid)
    }
}
```

### Sign: Certificate Enumeration and Signing

```go
package main

import (
    "fmt"
    "log"

    "github.com/M0Rf30/opencie-pkcs11-go/sign"
)

func main() {
    // Initialize signing context
    ctx := sign.SignInit()
    defer sign.SignCleanup(ctx)

    // Configure PKCS#11 module and slot
    if err := sign.SignSetString(ctx, sign.OptPKCS11, "/usr/lib/libopencie-pkcs11.so"); err != nil {
        log.Fatal(err)
    }
    if err := sign.SignSetInt(ctx, sign.OptSlot, 0); err != nil {
        log.Fatal(err)
    }

    // Get available certificates
    certs, err := sign.SignGetCertificates(ctx)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d certificate(s):\n", len(certs))
    for i, cert := range certs {
        fmt.Printf("%d. CN: %s, Valid: %s - %s\n", i+1, cert.CN, cert.ValidFrom, cert.Expiration)
    }

    if len(certs) == 0 {
        return
    }

    // Sign a PDF with the first certificate
    if err := sign.SignSetString(ctx, sign.OptPin, "12345678"); err != nil {
        log.Fatal(err)
    }
    if err := sign.SignSetString(ctx, sign.OptInputFile, "document.pdf"); err != nil {
        log.Fatal(err)
    }
    if err := sign.SignSetString(ctx, sign.OptOutputFile, "document_signed.pdf"); err != nil {
        log.Fatal(err)
    }
    if err := sign.SignSetInt(ctx, sign.OptInputFileType, sign.FileTypePDF); err != nil {
        log.Fatal(err)
    }
    if err := sign.SignSetString(ctx, sign.OptPDFSubfilter, sign.PDFSubfilterETSICAdES); err != nil {
        log.Fatal(err)
    }

    if err := sign.SignSign(ctx); err != nil {
        log.Fatal(err)
    }

    fmt.Println("Document signed successfully")
}
```

### Sign: Signature Verification

```go
package main

import (
    "fmt"
    "log"

    "github.com/M0Rf30/opencie-pkcs11-go/sign"
)

func main() {
    ctx := sign.VerifyInit()
    defer sign.VerifyCleanup(ctx)

    // Configure verification
    if err := sign.VerifySetString(ctx, sign.OptInputFile, "document_signed.pdf"); err != nil {
        log.Fatal(err)
    }
    if err := sign.VerifySetInt(ctx, sign.OptVerifyRevocation, 1); err != nil {
        log.Fatal(err)
    }
    if err := sign.VerifySetString(ctx, sign.OptCACertDir, "/etc/ssl/certs"); err != nil {
        log.Fatal(err)
    }

    // Perform verification
    result, err := sign.VerifyVerify(ctx)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Verification result: 0x%08X\n", result.ErrorCode)
    fmt.Printf("Found %d signer(s):\n", len(result.VerifyInfo.SignerInfos))

    for i, signer := range result.VerifyInfo.SignerInfos {
        fmt.Printf("%d. %s %s (%s)\n", i+1, signer.GivenName, signer.Surname, signer.CN)
        fmt.Printf("   Signed: %s\n", signer.SigningTime)
        fmt.Printf("   Valid: %s - %s\n", signer.ValidFrom, signer.Expiration)
        if signer.RevocationInfo != nil {
            fmt.Printf("   Revocation: %d\n", signer.RevocationInfo.RevocationStatus)
        }
    }
}
```

## Limitations

- **Callbacks**: The `cie` package does not fully support passing Go callbacks to C. Progress and completion callbacks must be passed as `nil`. A future version may implement a cookie-based mechanism to enable Go callback support.
- **Thread Safety**: The underlying C library uses locking; however, Go code should avoid concurrent calls to the same session or context from multiple goroutines without external synchronization.
- **Memory Management**: The bindings handle C memory allocation/deallocation internally. Do not manually free pointers returned by the C library.

## Platform Support

- **Linux** (x86_64, aarch64)
- **Windows** (x86_64, via MinGW-w64 cross-compilation)
- **macOS** (arm64)
- **Android** (arm64, experimental)

## License

This Go module is released under the same license as the underlying library (GPL-2.0-or-later).  
See the [opencie-pkcs11 LICENSE](https://github.com/M0Rf30/opencie-pkcs11/blob/main/LICENSE.md) for details.

## Links

- **Upstream C library**: [github.com/M0Rf30/opencie-pkcs11](https://github.com/M0Rf30/opencie-pkcs11)
- **Issues**: [github.com/M0Rf30/opencie-pkcs11-go/issues](https://github.com/M0Rf30/opencie-pkcs11-go/issues)
- **CIE Official Site**: [www.cartaidentita.interno.gov.it](https://www.cartaidentita.interno.gov.it/)

---

**Maintained by**: Gianluca Boiano ([@M0Rf30](https://github.com/M0Rf30))
