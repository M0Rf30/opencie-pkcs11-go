// Package cie provides cgo bindings for CIE-specific extensions
// exported by libopencie-pkcs11.
package cie

/*
#cgo LDFLAGS: -lopencie-pkcs11
#include <stdlib.h>
#include <string.h>

// CK_RV type and success code
#ifndef CK_RV
typedef unsigned long CK_RV;
#endif

#ifndef CKR_OK
#define CKR_OK 0x00000000UL
#endif

#include <opencie/cie_ext.h>

// Note: Callback support is not implemented. The C API allows NULL
// for all callback parameters, so we always pass NULL.
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

// RV represents a CK_RV return value from CIE functions.
type RV C.CK_RV

// Error implements the error interface for RV.
func (r RV) Error() string {
	return fmt.Sprintf("CIE CKR 0x%08X", uint64(r))
}

const (
	// CKR_OK indicates success.
	CKR_OK = RV(0x00000000)
	// CKR_BUFFER_TOO_SMALL is returned when an output buffer is undersized.
	CKR_BUFFER_TOO_SMALL = RV(0x00000150)
)

const (
	// MaxLen is OPENCIE_MAX_LEN from cie_ext.h.
	MaxLen = 512
	// rvCountLimit separates "this is a count" from "this is a CKR_*" return.
	// cie_verify and cie_get_sign_count return either a count (small) or a
	// CKR_* error code on failure. PKCS#11 error codes are >= 0x00000001 and
	// in practice >= 0x00000050; we treat anything below 0x1000 as a count.
	rvCountLimit C.CK_RV = 0x1000
)

// ProgressCallback is a placeholder type. Go callbacks are not currently
// passed through cgo to the C library; pass nil to functions that accept it.
type ProgressCallback func(progress int, message string) error

// CompletedCallback is a placeholder type. Pass nil.
type CompletedCallback func(pan, name, serial string) error

// SignCompletedCallback is a placeholder type. Pass nil.
type SignCompletedCallback func(ret int) error

// VerifyInfo contains information about a signature verification.
type VerifyInfo struct {
	Name            string
	Surname         string
	CN              string
	SigningTime     string
	CADN            string
	CertRevocStatus int
	IsSignValid     bool
	IsCertValid     bool
}

// Enable enrolls a CIE card identified by PAN using the 8-digit PIN.
// attempts will be set to the remaining PIN attempts on error if non-nil.
// Callbacks are not currently supported; pass nil.
func Enable(pan, pin string, attempts *int, progress ProgressCallback, completed CompletedCallback) error {
	cPan := C.CString(pan)
	cPin := C.CString(pin)
	defer C.free(unsafe.Pointer(cPan))
	defer C.free(unsafe.Pointer(cPin))

	var cAttempts C.int
	var attemptsPtr *C.int
	if attempts != nil {
		attemptsPtr = &cAttempts
	}

	rv := C.cie_enable(cPan, cPin, attemptsPtr, nil, nil)

	if attempts != nil {
		*attempts = int(cAttempts)
	}

	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// IsEnabled checks whether the card identified by PAN is currently enrolled.
// Returns true if enrolled, false if not.
func IsEnabled(pan string) bool {
	cPan := C.CString(pan)
	defer C.free(unsafe.Pointer(cPan))

	rv := C.cie_is_enabled(cPan)
	return rv == 1
}

// Disable removes the enrolment for the card identified by PAN.
func Disable(pan string) error {
	cPan := C.CString(pan)
	defer C.free(unsafe.Pointer(cPan))

	rv := C.cie_disable(cPan)
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// ChangePin changes the PIN from currentPIN to newPIN.
// attempts will be set to remaining attempts on error if non-nil.
func ChangePin(currentPIN, newPIN string, attempts *int, progress ProgressCallback) error {
	cCurrent := C.CString(currentPIN)
	cNew := C.CString(newPIN)
	defer C.free(unsafe.Pointer(cCurrent))
	defer C.free(unsafe.Pointer(cNew))

	var cAttempts C.int
	var attemptsPtr *C.int
	if attempts != nil {
		attemptsPtr = &cAttempts
	}

	rv := C.cie_change_pin(cCurrent, cNew, attemptsPtr, nil)

	if attempts != nil {
		*attempts = int(cAttempts)
	}

	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// UnblockPin unblocks the PIN using the PUK and sets a new PIN.
// attempts will be set to remaining PUK attempts on error if non-nil.
func UnblockPin(puk, newPIN string, attempts *int, progress ProgressCallback) error {
	cPuk := C.CString(puk)
	cNew := C.CString(newPIN)
	defer C.free(unsafe.Pointer(cPuk))
	defer C.free(unsafe.Pointer(cNew))

	var cAttempts C.int
	var attemptsPtr *C.int
	if attempts != nil {
		attemptsPtr = &cAttempts
	}

	rv := C.cie_unblock_pin(cPuk, cNew, attemptsPtr, nil)

	if attempts != nil {
		*attempts = int(cAttempts)
	}

	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// Sign signs a PDF on behalf of the card identified by pan.
//
// sigType is the signature type string ("PDF", "P7M", ...).
// page is the 0-based page index for the signature widget.
// x, y, w, h define the widget position and size in PDF points.
// imageData is the raw bytes of an optional signature image; pass nil for none.
//
// Callbacks are not currently supported; pass nil.
func Sign(
	inFile, sigType, pin, pan string,
	page int,
	x, y, w, h float32,
	imageData []byte,
	outFile string,
	progress ProgressCallback,
	signCompleted SignCompletedCallback,
) error {
	cInFile := C.CString(inFile)
	cType := C.CString(sigType)
	cPin := C.CString(pin)
	cPan := C.CString(pan)
	cOutFile := C.CString(outFile)
	defer C.free(unsafe.Pointer(cInFile))
	defer C.free(unsafe.Pointer(cType))
	defer C.free(unsafe.Pointer(cPin))
	defer C.free(unsafe.Pointer(cPan))
	defer C.free(unsafe.Pointer(cOutFile))

	var cImageData *C.uchar
	var cImageLen C.int
	if len(imageData) > 0 {
		cImageData = (*C.uchar)(unsafe.Pointer(&imageData[0]))
		cImageLen = C.int(len(imageData))
	}

	rv := C.cie_sign(
		cInFile, cType, cPin, cPan, C.int(page),
		C.float(x), C.float(y), C.float(w), C.float(h),
		cImageData, cImageLen,
		cOutFile, nil, nil,
	)

	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// Verify verifies a signed document.
//
// proxyAddr is an optional HTTP proxy address (empty for none).
// proxyPort is the proxy port (0 for none).
// usrPass is the optional proxy "user:pass" credential string.
//
// Returns the number of valid signatures found.
func Verify(inFile, proxyAddr string, proxyPort int, usrPass string) (int, error) {
	cInFile := C.CString(inFile)
	defer C.free(unsafe.Pointer(cInFile))

	var cProxyAddr *C.char
	if proxyAddr != "" {
		cProxyAddr = C.CString(proxyAddr)
		defer C.free(unsafe.Pointer(cProxyAddr))
	}

	var cUsrPass *C.char
	if usrPass != "" {
		cUsrPass = C.CString(usrPass)
		defer C.free(unsafe.Pointer(cUsrPass))
	}

	rv := C.cie_verify(cInFile, cProxyAddr, C.int(proxyPort), cUsrPass)

	// CK_RV is unsigned, so a "rv < 0" check would always be false.
	// The C API overloads the return value: small numbers are signature
	// counts, large numbers are CKR_* error codes.
	if rv >= rvCountLimit {
		return 0, RV(rv)
	}
	return int(rv), nil
}

// GetSignCount returns the number of signatures found by the last Verify call.
func GetSignCount() (int, error) {
	rv := C.cie_get_sign_count()
	if rv >= rvCountLimit {
		return 0, RV(rv)
	}
	return int(rv), nil
}

// GetVerifyInfo retrieves signer information for the n-th signature found by
// the last Verify call. index is zero-based.
func GetVerifyInfo(index int) (*VerifyInfo, error) {
	var cInfo C.struct_verifyInfo_t
	rv := C.cie_get_verify_info(C.int(index), &cInfo)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	info := &VerifyInfo{
		Name:            C.GoString(&cInfo.name[0]),
		Surname:         C.GoString(&cInfo.surname[0]),
		CN:              C.GoString(&cInfo.cn[0]),
		SigningTime:     C.GoString(&cInfo.signingTime[0]),
		CADN:            C.GoString(&cInfo.cadn[0]),
		CertRevocStatus: int(cInfo.CertRevocStatus),
		IsSignValid:     cInfo.isSignValid != 0,
		IsCertValid:     cInfo.isCertValid != 0,
	}

	return info, nil
}

// ExtractP7M extracts the original (unwrapped) document from a .p7m envelope.
func ExtractP7M(inFile, outFile string) error {
	cInFile := C.CString(inFile)
	cOutFile := C.CString(outFile)
	defer C.free(unsafe.Pointer(cInFile))
	defer C.free(unsafe.Pointer(cOutFile))

	rv := C.cie_extract_p7m(cInFile, cOutFile)
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// ReaderCount returns the number of currently attached PC/SC readers.
func ReaderCount() int {
	return int(C.cie_reader_count())
}

// ReaderWatch blocks until the reader count changes from currentCount, and
// returns the new reader count.
func ReaderWatch(currentCount int) int {
	return int(C.cie_reader_watch(C.int(currentCount)))
}

// ReaderName returns the name of the first attached reader.
// Returns an empty string if no reader is attached.
func ReaderName() (string, error) {
	const bufLen = 256
	buf := make([]byte, bufLen)
	n := C.cie_reader_name((*C.char)(unsafe.Pointer(&buf[0])), C.int(bufLen))
	if n < 0 {
		return "", fmt.Errorf("cie_reader_name failed: %d", int(n))
	}
	if n == 0 {
		return "", nil
	}
	// Trim at NUL or use exact length if the C side reports it.
	end := int(n)
	if end > bufLen {
		end = bufLen
	}
	for i := 0; i < end; i++ {
		if buf[i] == 0 {
			end = i
			break
		}
	}
	return string(buf[:end]), nil
}

// ErrDigestInfoBufferTooSmall is returned by MakeDigestInfo when the internal
// buffer is too small. The caller can ignore the error and rely on the retry
// loop in MakeDigestInfo, or treat it as a programming error.
var ErrDigestInfoBufferTooSmall = errors.New("digest info buffer too small")

// MakeDigestInfo builds an ASN.1 DigestInfo structure for the given digest
// algorithm identifier (algid) and digest bytes. The returned slice contains
// the encoded DigestInfo suitable for use with PKCS#11 raw RSA signing.
func MakeDigestInfo(algid int, digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("digest is empty")
	}
	// DigestInfo for SHA-512 is the largest common case and fits well under
	// 256 bytes. Start at 256 and grow on CKR_BUFFER_TOO_SMALL.
	bufLen := C.size_t(256)
	for attempts := 0; attempts < 4; attempts++ {
		out := make([]byte, bufLen)
		ok := C.make_digest_info(
			C.int(algid),
			(*C.uchar)(unsafe.Pointer(&digest[0])),
			C.size_t(len(digest)),
			(*C.uchar)(unsafe.Pointer(&out[0])),
			&bufLen,
		)
		if ok == 1 {
			return out[:bufLen], nil
		}
		// Buffer was too small; bufLen has been updated by the C side, but
		// also grow defensively in case it didn't.
		if bufLen < 1024 {
			bufLen *= 2
		} else {
			bufLen += 512
		}
	}
	return nil, ErrDigestInfoBufferTooSmall
}
