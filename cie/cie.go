// SPDX-License-Identifier: MPL-2.0

// Package cie provides cgo bindings for CIE-specific extensions
// exported by libopencie-pkcs11 (include/opencie/cie_ext.h).
//
// The bindings target libopencie-pkcs11 1.3.0 or newer.
package cie

/*
#cgo LDFLAGS: -lopencie-pkcs11
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <opencie/cie_ext.h>

// Layout guard: verifyInfo_t is five char[2*OPENCIE_MAX_LEN] buffers followed
// by three ints. A header change that breaks the Go side fails the build.
_Static_assert(OPENCIE_MAX_LEN == 512, "OPENCIE_MAX_LEN changed");
_Static_assert(sizeof(struct verifyInfo_t) ==
                   5 * OPENCIE_MAX_LEN * 2 + 3 * sizeof(int),
               "struct verifyInfo_t layout changed");

// The C library calls PROGRESS_CALLBACK / COMPLETED_CALLBACK /
// SIGN_COMPLETED_CALLBACK unconditionally ("must not be NULL" in cie_ext.h),
// so we always hand it these trampolines (defined in callbacks.c), which
// forward to the exported Go functions below.
CK_RV opencie_go_progress(int progress, const char* message);
CK_RV opencie_go_completed(const char* pan, const char* name,
                           const char* serial);
CK_RV opencie_go_sign_completed(int ret);
*/
import "C"
import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

// RV represents a CK_RV return value from CIE functions.
//
// CK_RV is "unsigned long": 64-bit on LP64 platforms and 32-bit on Windows.
// RV follows the C type, so comparisons against the constants below are
// correct on both.
type RV C.CK_RV

// Error implements the error interface for RV.
func (r RV) Error() string {
	if name, ok := rvNames[r]; ok {
		return fmt.Sprintf("CIE CKR 0x%08X (%s)", uint64(r), name)
	}
	return fmt.Sprintf("CIE CKR 0x%08X", uint64(r))
}

// PKCS#11 return codes the CIE extension functions can report.
const (
	// CKR_OK indicates success.
	CKR_OK = RV(0x00000000)
	// CKR_HOST_MEMORY indicates an allocation failure inside the library.
	CKR_HOST_MEMORY = RV(0x00000002)
	// CKR_GENERAL_ERROR is an unspecified failure.
	CKR_GENERAL_ERROR = RV(0x00000005)
	// CKR_FUNCTION_FAILED is returned, for example, by Disable when the card
	// was not enrolled.
	CKR_FUNCTION_FAILED = RV(0x00000006)
	// CKR_ARGUMENTS_BAD indicates an invalid argument (for example a CAN
	// that is not exactly six digits).
	CKR_ARGUMENTS_BAD = RV(0x00000007)
	// CKR_DEVICE_ERROR indicates a reader/card communication failure.
	CKR_DEVICE_ERROR = RV(0x00000030)
	// CKR_FUNCTION_NOT_SUPPORTED is returned by ReadDGSCan when the chip has
	// no EF.CardAccess / supported PACE protocol.
	CKR_FUNCTION_NOT_SUPPORTED = RV(0x00000054)
	// CKR_PIN_INCORRECT is returned for a wrong PIN, or for a wrong CAN in
	// ReadDGSCan (see ErrWrongCan).
	CKR_PIN_INCORRECT = RV(0x000000A0)
	// CKR_PIN_INVALID indicates a PIN with invalid characters.
	CKR_PIN_INVALID = RV(0x000000A1)
	// CKR_PIN_LEN_RANGE indicates a PIN of the wrong length.
	CKR_PIN_LEN_RANGE = RV(0x000000A2)
	// CKR_PIN_LOCKED indicates the PIN is blocked.
	CKR_PIN_LOCKED = RV(0x000000A4)
	// CKR_TOKEN_NOT_PRESENT indicates no card is on the reader.
	CKR_TOKEN_NOT_PRESENT = RV(0x000000E0)
	// CKR_TOKEN_NOT_RECOGNIZED indicates a card that is not a supported CIE.
	CKR_TOKEN_NOT_RECOGNIZED = RV(0x000000E1)
	// CKR_BUFFER_TOO_SMALL is returned when an output buffer is undersized.
	CKR_BUFFER_TOO_SMALL = RV(0x00000150)
)

// CIE signing SDK error codes (CIE_SIGN_ERROR_* in the library), returned as
// RV by Verify, ExtractP7M, Sign and Timestamp. They all lie at or above
// SignErrorBase.
const (
	// SignErrorBase is CIE_SIGN_ERROR_BASE.
	SignErrorBase = RV(0x84000000)
	// SignErrUnexpected is CIE_SIGN_ERROR_UNEXPECTED.
	SignErrUnexpected = SignErrorBase + 1
	// SignErrFileNotFound is CIE_SIGN_ERROR_FILE_NOT_FOUND.
	SignErrFileNotFound = SignErrorBase + 2
	// SignErrDetachedPKCS7 is CIE_SIGN_ERROR_DETACHED_PKCS7.
	SignErrDetachedPKCS7 = SignErrorBase + 3
	// SignErrCertRevoked is CIE_SIGN_ERROR_CERT_REVOKED.
	SignErrCertRevoked = SignErrorBase + 4
	// SignErrInvalidFile is CIE_SIGN_ERROR_INVALID_FILE.
	SignErrInvalidFile = SignErrorBase + 5
	// SignErrInvalidP11 is CIE_SIGN_ERROR_INVALID_P11.
	SignErrInvalidP11 = SignErrorBase + 6
	// SignErrInvalidAlias is CIE_SIGN_ERROR_INVALID_ALIAS.
	SignErrInvalidAlias = SignErrorBase + 7
	// SignErrInvalidSigOpt is CIE_SIGN_ERROR_INVALID_SIGOPT.
	SignErrInvalidSigOpt = SignErrorBase + 8
	// SignErrCertInvalid is CIE_SIGN_ERROR_CERT_INVALID.
	SignErrCertInvalid = SignErrorBase + 9
	// SignErrCertExpired is CIE_SIGN_ERROR_CERT_EXPIRED.
	SignErrCertExpired = SignErrorBase + 10
	// SignErrCACertNotFound is CIE_SIGN_ERROR_CACERT_NOTFOUND.
	SignErrCACertNotFound = SignErrorBase + 11
	// SignErrCertNotFound is CIE_SIGN_ERROR_CERT_NOTFOUND.
	SignErrCertNotFound = SignErrorBase + 12
	// SignErrCertNotForSignature is CIE_SIGN_ERROR_CERT_NOT_FOR_SIGNATURE.
	SignErrCertNotForSignature = SignErrorBase + 13
	// SignErrTSLLoad is CIE_SIGN_ERROR_TSL_LOAD.
	SignErrTSLLoad = SignErrorBase + 20
	// SignErrTSLParse is CIE_SIGN_ERROR_TSL_PARSE.
	SignErrTSLParse = SignErrorBase + 21
	// SignErrTSLInvalid is CIE_SIGN_ERROR_TSL_INVALID.
	SignErrTSLInvalid = SignErrorBase + 22
	// SignErrTSLCACertDirNotSet is CIE_SIGN_ERROR_TSL_CACERTDIR_NOT_SET.
	SignErrTSLCACertDirNotSet = SignErrorBase + 23
	// SignErrTSA is CIE_SIGN_ERROR_TSA.
	SignErrTSA = SignErrorBase + 30
)

var rvNames = map[RV]string{
	CKR_HOST_MEMORY:            "CKR_HOST_MEMORY",
	CKR_GENERAL_ERROR:          "CKR_GENERAL_ERROR",
	CKR_FUNCTION_FAILED:        "CKR_FUNCTION_FAILED",
	CKR_ARGUMENTS_BAD:          "CKR_ARGUMENTS_BAD",
	CKR_DEVICE_ERROR:           "CKR_DEVICE_ERROR",
	CKR_FUNCTION_NOT_SUPPORTED: "CKR_FUNCTION_NOT_SUPPORTED",
	CKR_PIN_INCORRECT:          "CKR_PIN_INCORRECT",
	CKR_PIN_INVALID:            "CKR_PIN_INVALID",
	CKR_PIN_LEN_RANGE:          "CKR_PIN_LEN_RANGE",
	CKR_PIN_LOCKED:             "CKR_PIN_LOCKED",
	CKR_TOKEN_NOT_PRESENT:      "CKR_TOKEN_NOT_PRESENT",
	CKR_TOKEN_NOT_RECOGNIZED:   "CKR_TOKEN_NOT_RECOGNIZED",
	CKR_BUFFER_TOO_SMALL:       "CKR_BUFFER_TOO_SMALL",
}

const (
	// MaxLen is OPENCIE_MAX_LEN from cie_ext.h. Every string field of
	// verifyInfo_t is a char[2*MaxLen] buffer.
	MaxLen = C.OPENCIE_MAX_LEN

	// maxSignCount is the largest value cie_verify / cie_get_sign_count can
	// return as a signature count. Anything above it is an error code:
	// CIE_SIGN_ERROR_* (0x84000000 and up) or a negative status cast to
	// CK_RV (>= 0x80000000 in 32 bits, and in 64 bits).
	maxSignCount = RV(math.MaxInt32)

	// MRZBufferSize is the capacity of the DG1 buffer ReadDGS and ReadDGSCan
	// pass to the library (the header recommends at least 4096 bytes).
	MRZBufferSize = 4096
	// PhotoBufferSize is the capacity of the photo buffer ReadDGS and
	// ReadDGSCan pass to the library (the header recommends at least
	// 524288 bytes).
	PhotoBufferSize = 524288
)

// Layout of the C structs as seen by cgo; checked by the unit tests.
var (
	verifyInfoSize            = uintptr(C.sizeof_struct_verifyInfo_t)
	verifyInfoCertRevocOffset = unsafe.Offsetof(C.struct_verifyInfo_t{}.CertRevocStatus)
	verifyInfoIsSignOffset    = unsafe.Offsetof(C.struct_verifyInfo_t{}.isSignValid)
	verifyInfoIsCertOffset    = unsafe.Offsetof(C.struct_verifyInfo_t{}.isCertValid)
	verifyInfoNameLen         = unsafe.Sizeof(C.struct_verifyInfo_t{}.name)
)

// ErrorKind is a semantic classification of a CIE card failure,
// derived from the ISO 7816 status word (cie_error_kind).
type ErrorKind C.cie_error_kind

const (
	// ErrNone indicates no error.
	ErrNone ErrorKind = 0
	// ErrWrongPin indicates an incorrect PIN (0x63Cx, 0x6300, 0x6700).
	ErrWrongPin ErrorKind = 1
	// ErrPinBlocked indicates the PIN is blocked (0x6983).
	ErrPinBlocked ErrorKind = 2
	// ErrPinNotSet indicates the PIN has not been set (0x6984).
	ErrPinNotSet ErrorKind = 3
	// ErrSecurityNotSatisfied indicates a security condition not met
	// (0x6982).
	ErrSecurityNotSatisfied ErrorKind = 4
	// ErrFileNotFound indicates a file was not found (0x6A82).
	ErrFileNotFound ErrorKind = 5
	// ErrWrongParams indicates incorrect parameters (0x6A80, 0x6A86,
	// 0x6A88, 0x6B00).
	ErrWrongParams ErrorKind = 6
	// ErrInsNotSupported indicates an unsupported instruction (0x6D00,
	// 0x6E00). ReadDGSCan also reports it (with CKR_DEVICE_ERROR) when the
	// reader cannot send the extended-length APDUs PACE needs.
	ErrInsNotSupported ErrorKind = 7
	// ErrCardCommunication indicates a card communication failure
	// (transport/SM failure with no usable status word).
	ErrCardCommunication ErrorKind = 8
	// ErrUnknown indicates an unclassified status word.
	ErrUnknown ErrorKind = 9
	// ErrUnsupportedCard indicates the card answered but its chip/applet is
	// not in the supported list.
	ErrUnsupportedCard ErrorKind = 10
	// ErrWrongCan indicates PACE rejected the CAN (mutual authentication
	// failed). Reported by ReadDGSCan together with CKR_PIN_INCORRECT.
	ErrWrongCan ErrorKind = 11
)

var errorKindNames = map[ErrorKind]string{
	ErrNone:                 "none",
	ErrWrongPin:             "wrong PIN",
	ErrPinBlocked:           "PIN blocked",
	ErrPinNotSet:            "PIN not set",
	ErrSecurityNotSatisfied: "security status not satisfied",
	ErrFileNotFound:         "file not found",
	ErrWrongParams:          "wrong parameters",
	ErrInsNotSupported:      "instruction not supported",
	ErrCardCommunication:    "card communication failure",
	ErrUnknown:              "unknown status word",
	ErrUnsupportedCard:      "unsupported card",
	ErrWrongCan:             "wrong CAN",
}

// String returns a short human-readable name for the error kind.
func (k ErrorKind) String() string {
	if s, ok := errorKindNames[k]; ok {
		return s
	}
	return fmt.Sprintf("ErrorKind(%d)", uint32(k))
}

// Sentinel errors reported (through errors.Is) by ReadDGS and ReadDGSCan.
var (
	// ErrCANRejected means PACE rejected the CAN: it is wrong. The library
	// never retries a wrong CAN on its own; ask the user to re-read it from
	// the card.
	ErrCANRejected = errors.New("cie: CAN rejected by the card")
	// ErrExtendedAPDUNotSupported means the reader (or transport) does not
	// support the extended-length APDUs PACE needs, e.g. short-APDU-only
	// readers such as the ACS ACR122U. Fall back to ReadDGS (PIN based), or
	// use another reader.
	ErrExtendedAPDUNotSupported = errors.New("cie: reader does not support extended-length APDUs")
	// ErrPACENotSupported means the chip has no EF.CardAccess or no
	// supported PACE protocol.
	ErrPACENotSupported = errors.New("cie: card does not support PACE")
)

// CardError is returned by ReadDGS and ReadDGSCan: the PKCS#11 return code
// together with the thread-local detail from cie_last_error.
//
// errors.Is matches ErrCANRejected, ErrExtendedAPDUNotSupported and
// ErrPACENotSupported; errors.As can extract the underlying RV.
type CardError struct {
	// RV is the CK_RV returned by the C function.
	RV RV
	// Kind is the semantic classification (ErrNone if the library recorded
	// none, e.g. for CKR_ARGUMENTS_BAD).
	Kind ErrorKind
	// SW is the raw ISO 7816 status word, or 0 if the failure carried none.
	SW uint16
}

// Error implements the error interface.
func (e *CardError) Error() string {
	if e.SW != 0 {
		return fmt.Sprintf("%v: %v (SW 0x%04X)", e.RV, e.Kind, e.SW)
	}
	return fmt.Sprintf("%v: %v", e.RV, e.Kind)
}

// Unwrap returns the underlying RV.
func (e *CardError) Unwrap() error { return e.RV }

// Is reports whether e matches one of the package sentinel errors.
func (e *CardError) Is(target error) bool {
	switch target {
	case ErrCANRejected:
		return e.Kind == ErrWrongCan
	case ErrExtendedAPDUNotSupported:
		return e.RV == CKR_DEVICE_ERROR && e.Kind == ErrInsNotSupported
	case ErrPACENotSupported:
		return e.Kind == ErrUnsupportedCard
	}
	return false
}

// classifyReadError builds the error ReadDGS/ReadDGSCan return for a failed
// call. It is a pure function.
func classifyReadError(rv RV, kind ErrorKind, sw uint16) error {
	return &CardError{RV: rv, Kind: kind, SW: sw}
}

// ProgressCallback receives progress notifications (progress is 0-100) during
// long operations. It runs on the goroutine that called the CIE function,
// while the C library is mid-operation: it must return quickly and must not
// call back into this package. A non-nil error is reported to the library as
// a CK_RV (an RV is passed through, anything else becomes
// CKR_FUNCTION_FAILED); libopencie-pkcs11 1.3.0 ignores the value.
type ProgressCallback func(progress int, message string) error

// CompletedCallback is called once when Enable finishes pairing a card.
// The same restrictions as ProgressCallback apply.
type CompletedCallback func(pan, name, serial string) error

// SignCompletedCallback is called once when Sign finishes; ret is the
// library's result code (0 = success). The same restrictions as
// ProgressCallback apply.
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

// DataGroups holds the chip data groups read by ReadDGS and ReadDGSCan.
type DataGroups struct {
	// MRZ is the raw DG1 TLV (ICAO 9303), not a printable string.
	MRZ []byte
	// Photo is the DG2 portrait as PNG (JPEG2000 is decoded by the library).
	Photo []byte
}

// ---------------------------------------------------------------------------
// Callback plumbing
// ---------------------------------------------------------------------------

// The C callbacks carry no user-data pointer, so the Go callbacks of the call
// in flight live in package state. cbState.mu serialises the calls that take
// callbacks; the trampolines run on the goroutine holding the lock.
type callbackSet struct {
	progress      ProgressCallback
	completed     CompletedCallback
	signCompleted SignCompletedCallback
}

var cbState struct {
	mu       sync.Mutex
	cur      callbackSet
	panicked bool
	panicVal any
}

// runWithCallbacks runs call with set installed as the active callbacks.
// A panic in a callback is caught on the C boundary (it must not unwind
// through C++ frames) and re-raised here once the C call has returned.
func runWithCallbacks(set callbackSet, call func()) {
	cbState.mu.Lock()
	defer cbState.mu.Unlock()
	cbState.cur = set
	cbState.panicked = false
	cbState.panicVal = nil
	defer func() { cbState.cur = callbackSet{} }()

	call()

	if cbState.panicked {
		v := cbState.panicVal
		cbState.panicked, cbState.panicVal = false, nil
		panic(v)
	}
}

// errorToRV maps a callback error to the CK_RV handed back to the library.
func errorToRV(err error) RV {
	if err == nil {
		return CKR_OK
	}
	var rv RV
	if errors.As(err, &rv) {
		return rv
	}
	return CKR_FUNCTION_FAILED
}

func invokeCallback(f func() error) (rv RV) {
	defer func() {
		if r := recover(); r != nil {
			if !cbState.panicked {
				cbState.panicked, cbState.panicVal = true, r
			}
			rv = CKR_GENERAL_ERROR
		}
	}()
	return errorToRV(f())
}

//export goCieProgress
func goCieProgress(progress C.int, message *C.char) C.CK_RV {
	return C.CK_RV(invokeCallback(func() error {
		if cb := cbState.cur.progress; cb != nil {
			return cb(int(progress), C.GoString(message))
		}
		return nil
	}))
}

//export goCieCompleted
func goCieCompleted(pan, name, serial *C.char) C.CK_RV {
	return C.CK_RV(invokeCallback(func() error {
		if cb := cbState.cur.completed; cb != nil {
			return cb(C.GoString(pan), C.GoString(name), C.GoString(serial))
		}
		return nil
	}))
}

//export goCieSignCompleted
func goCieSignCompleted(ret C.int) C.CK_RV {
	return C.CK_RV(invokeCallback(func() error {
		if cb := cbState.cur.signCompleted; cb != nil {
			return cb(int(ret))
		}
		return nil
	}))
}

func progressFn() C.PROGRESS_CALLBACK {
	return C.PROGRESS_CALLBACK(C.opencie_go_progress)
}

func completedFn() C.COMPLETED_CALLBACK {
	return C.COMPLETED_CALLBACK(C.opencie_go_completed)
}

func signCompletedFn() C.SIGN_COMPLETED_CALLBACK {
	return C.SIGN_COMPLETED_CALLBACK(C.opencie_go_sign_completed)
}

// freeSecret wipes and frees a C string holding a PIN/PUK.
func freeSecret(p *C.char) {
	C.memset(unsafe.Pointer(p), 0, C.strlen(p))
	C.free(unsafe.Pointer(p))
}

// ---------------------------------------------------------------------------
// Enrolment
// ---------------------------------------------------------------------------

// Enable enrolls a CIE card identified by PAN using the 8-digit PIN.
// attempts will be set to the remaining PIN attempts on error if non-nil.
// progress and completed may be nil.
func Enable(pan, pin string, attempts *int, progress ProgressCallback, completed CompletedCallback) error {
	cPan := C.CString(pan)
	cPin := C.CString(pin)
	defer C.free(unsafe.Pointer(cPan))
	defer freeSecret(cPin)

	var cAttempts C.int
	var attemptsPtr *C.int
	if attempts != nil {
		attemptsPtr = &cAttempts
	}

	var rv C.CK_RV
	runWithCallbacks(callbackSet{progress: progress, completed: completed}, func() {
		rv = C.cie_enable(cPan, cPin, attemptsPtr, progressFn(), completedFn())
	})

	if attempts != nil {
		*attempts = int(cAttempts)
	}

	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// IsEnabled checks whether the card identified by PAN is enrolled, that is,
// whether the local cache (~/.CIEPKI) holds an entry for it. Cards paired
// through the official IPZS CIE ID app are recognised through its pairing
// cache. A card that is merely present on a reader is not "enabled".
//
// Since libopencie-pkcs11 1.3.0, cie_is_enabled returns 1 only if a cache
// exists; the PAN of a card on the reader is no longer enough.
func IsEnabled(pan string) bool {
	cPan := C.CString(pan)
	defer C.free(unsafe.Pointer(cPan))

	rv := C.cie_is_enabled(cPan)
	return rv == 1
}

// Disable removes the enrolment for the card identified by PAN. It returns
// CKR_FUNCTION_FAILED if the card was not enrolled.
func Disable(pan string) error {
	cPan := C.CString(pan)
	defer C.free(unsafe.Pointer(cPan))

	rv := C.cie_disable(cPan)
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// GetCertificate returns the DER-encoded X.509 certificate of a paired card.
//
// It reads the cache written by Enable and, when there is none and the card
// is on a reader, the CIE ID pairing cache (~/.CIEPKI/<PAN>.cache), which
// needs the card present to decrypt; the result is then cached for later
// calls. The card never releases the certificate without a verified PIN, so
// an unpaired card fails here.
//
// The buffer allocated by the library is copied and released with cie_free;
// the returned slice is owned by the caller.
func GetCertificate(pan string) ([]byte, error) {
	cPan := C.CString(pan)
	defer C.free(unsafe.Pointer(cPan))

	var out *C.uchar
	var outLen C.ulong
	rv := C.cie_get_certificate(cPan, &out, &outLen)
	if out != nil {
		// Always release through cie_free, never C.free: on Windows the DLL
		// and the caller may use different CRT heaps.
		defer C.cie_free(unsafe.Pointer(out))
	}
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}
	if out == nil || uint64(outLen) > math.MaxInt32 {
		return nil, CKR_FUNCTION_FAILED
	}
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// ---------------------------------------------------------------------------
// PIN management
// ---------------------------------------------------------------------------

// ChangePin changes the PIN from currentPIN to newPIN.
// attempts will be set to remaining attempts on error if non-nil.
// progress may be nil.
func ChangePin(currentPIN, newPIN string, attempts *int, progress ProgressCallback) error {
	cCurrent := C.CString(currentPIN)
	cNew := C.CString(newPIN)
	defer freeSecret(cCurrent)
	defer freeSecret(cNew)

	var cAttempts C.int
	var attemptsPtr *C.int
	if attempts != nil {
		attemptsPtr = &cAttempts
	}

	var rv C.CK_RV
	runWithCallbacks(callbackSet{progress: progress}, func() {
		rv = C.cie_change_pin(cCurrent, cNew, attemptsPtr, progressFn())
	})

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
// progress may be nil.
func UnblockPin(puk, newPIN string, attempts *int, progress ProgressCallback) error {
	cPuk := C.CString(puk)
	cNew := C.CString(newPIN)
	defer freeSecret(cPuk)
	defer freeSecret(cNew)

	var cAttempts C.int
	var attemptsPtr *C.int
	if attempts != nil {
		attemptsPtr = &cAttempts
	}

	var rv C.CK_RV
	runWithCallbacks(callbackSet{progress: progress}, func() {
		rv = C.cie_unblock_pin(cPuk, cNew, attemptsPtr, progressFn())
	})

	if attempts != nil {
		*attempts = int(cAttempts)
	}

	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Sign & verify
// ---------------------------------------------------------------------------

// ErrImageTooLarge is returned by Sign when imageData does not fit the C
// API's int length parameter.
var ErrImageTooLarge = errors.New("cie: signature image too large")

// Sign signs a document on behalf of the card identified by pan.
//
// sigType is the signature type string ("PDF", "P7M", ...).
// page is the 0-based page index for the signature widget.
// x, y, w, h are fractions (0.0-1.0) of the page crop box: x is the left and
// y the bottom position, w and h the width and height. A w or h of 0 hides
// the visible widget.
// imageData is the PNG image for the signature stamp; pass nil for none.
// progress and signCompleted may be nil.
func Sign(
	inFile, sigType, pin, pan string,
	page int,
	x, y, w, h float32,
	imageData []byte,
	outFile string,
	progress ProgressCallback,
	signCompleted SignCompletedCallback,
) error {
	if len(imageData) > math.MaxInt32 {
		return ErrImageTooLarge
	}
	if page < math.MinInt32 || page > math.MaxInt32 {
		return CKR_ARGUMENTS_BAD
	}

	cInFile := C.CString(inFile)
	cType := C.CString(sigType)
	cPin := C.CString(pin)
	cPan := C.CString(pan)
	cOutFile := C.CString(outFile)
	defer C.free(unsafe.Pointer(cInFile))
	defer C.free(unsafe.Pointer(cType))
	defer freeSecret(cPin)
	defer C.free(unsafe.Pointer(cPan))
	defer C.free(unsafe.Pointer(cOutFile))

	var cImageData *C.uchar
	var cImageLen C.int
	if len(imageData) > 0 {
		cImageData = (*C.uchar)(unsafe.Pointer(&imageData[0]))
		cImageLen = C.int(len(imageData))
	}

	var rv C.CK_RV
	runWithCallbacks(callbackSet{progress: progress, signCompleted: signCompleted}, func() {
		rv = C.cie_sign(
			cInFile, cType, cPin, cPan, C.int(page),
			C.float(x), C.float(y), C.float(w), C.float(h),
			cImageData, cImageLen,
			cOutFile, progressFn(), signCompletedFn(),
		)
	})

	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// classifySignCount interprets the CK_RV of cie_verify together with the
// CK_RV of cie_get_sign_count taken right after it.
//
// cie_verify returns the number of signatures found, 0 if there are none, or
// an error code: a CIE_SIGN_ERROR_* value (0x84000000 and up) or a negative
// status cast to CK_RV. A return value that differs from cie_get_sign_count()
// is an error; so is a value above maxSignCount (both calls can report the
// same error code). Checking only "< 0" or "!= 0" is wrong: CK_RV is
// unsigned and a count is a legitimate non-zero value.
func classifySignCount(rv, count RV) (int, error) {
	if rv != count || rv > maxSignCount {
		return 0, rv
	}
	return int(rv), nil
}

// verifyMu keeps Verify's cie_verify + cie_get_sign_count pair atomic with
// respect to other Verify calls; the library keeps the result in global
// state that GetSignCount and GetVerifyInfo read.
var verifyMu sync.Mutex

// Verify verifies a signed document.
//
// proxyAddr is an optional HTTP proxy address (empty for none).
// proxyPort is the proxy port (0 for none).
// usrPass is the optional proxy "user:pass" credential string.
//
// Returns the number of signatures found (also reported by GetSignCount),
// 0 if the file has none. When no signature could be read the error is an RV
// holding a CIE_SIGN_ERROR_* code (see SignErrorBase) or a negative status
// cast to CK_RV.
func Verify(inFile, proxyAddr string, proxyPort int, usrPass string) (int, error) {
	if proxyPort < math.MinInt32 || proxyPort > math.MaxInt32 {
		return 0, CKR_ARGUMENTS_BAD
	}

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
		defer freeSecret(cUsrPass)
	}

	verifyMu.Lock()
	defer verifyMu.Unlock()

	rv := C.cie_verify(cInFile, cProxyAddr, C.int(proxyPort), cUsrPass)
	count := C.cie_get_sign_count()
	return classifySignCount(RV(rv), RV(count))
}

// GetSignCount returns the number of signatures found by the last Verify call.
func GetSignCount() (int, error) {
	verifyMu.Lock()
	defer verifyMu.Unlock()

	rv := RV(C.cie_get_sign_count())
	if rv > maxSignCount {
		return 0, rv
	}
	return int(rv), nil
}

// GetVerifyInfo retrieves signer information for the n-th signature found by
// the last Verify call. index is zero-based.
func GetVerifyInfo(index int) (*VerifyInfo, error) {
	if index < 0 || index > math.MaxInt32 {
		return nil, CKR_ARGUMENTS_BAD
	}

	verifyMu.Lock()
	defer verifyMu.Unlock()

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

// Timestamp requests a standalone RFC 3161 timestamp for a file. No card is
// needed: the SHA-256 digest of inFile is sent to the TSA at tsaURL and the
// DER-encoded TimeStampToken is written to outToken.
//
// tsaUsername and tsaPassword are optional HTTP Basic credentials (empty for
// none). progress may be nil.
func Timestamp(inFile, tsaURL, tsaUsername, tsaPassword, outToken string, progress ProgressCallback) error {
	cInFile := C.CString(inFile)
	cURL := C.CString(tsaURL)
	cOut := C.CString(outToken)
	defer C.free(unsafe.Pointer(cInFile))
	defer C.free(unsafe.Pointer(cURL))
	defer C.free(unsafe.Pointer(cOut))

	var cUser, cPass *C.char
	if tsaUsername != "" {
		cUser = C.CString(tsaUsername)
		defer C.free(unsafe.Pointer(cUser))
	}
	if tsaPassword != "" {
		cPass = C.CString(tsaPassword)
		defer freeSecret(cPass)
	}

	var rv C.CK_RV
	runWithCallbacks(callbackSet{progress: progress}, func() {
		rv = C.cie_timestamp(cInFile, cURL, cUser, cPass, cOut, progressFn())
	})

	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Chip data groups (ICAO 9303)
// ---------------------------------------------------------------------------

// readDGs runs one of the cie_read_dgs* C functions with the recommended
// buffer sizes and attaches cie_last_error detail to a failure.
func readDGs(call func(mrz *C.char, mrzLen *C.size_t, photo *C.uchar, photoLen *C.size_t) C.CK_RV) (*DataGroups, error) {
	// cie_last_error is thread-local: keep the call and the lookup on one
	// OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	mrz := make([]byte, MRZBufferSize)
	photo := make([]byte, PhotoBufferSize)
	mrzLen := C.size_t(len(mrz))
	photoLen := C.size_t(len(photo))

	rv := call(
		(*C.char)(unsafe.Pointer(&mrz[0])), &mrzLen,
		(*C.uchar)(unsafe.Pointer(&photo[0])), &photoLen,
	)
	if rv != C.CKR_OK {
		kind, sw := LastError()
		return nil, classifyReadError(RV(rv), kind, sw)
	}
	if uint64(mrzLen) > uint64(len(mrz)) || uint64(photoLen) > uint64(len(photo)) {
		return nil, CKR_GENERAL_ERROR
	}
	return &DataGroups{MRZ: mrz[:mrzLen:mrzLen], Photo: photo[:photoLen:photoLen]}, nil
}

// ReadDGSCan reads DG1 (MRZ) and DG2 (portrait) over ICAO 9303 PACE with the
// 6-digit Card Access Number (CAN) printed on the card. No PIN is used or
// consumed.
//
// can must be exactly six ASCII digits, otherwise the error is
// CKR_ARGUMENTS_BAD. Failures are *CardError values:
//
//   - wrong CAN: CKR_PIN_INCORRECT, kind ErrWrongCan
//     (errors.Is(err, ErrCANRejected)); never retried automatically with the
//     same CAN, so do not loop on it;
//   - chip without EF.CardAccess or a supported PACE protocol:
//     CKR_FUNCTION_NOT_SUPPORTED, kind ErrUnsupportedCard
//     (errors.Is(err, ErrPACENotSupported));
//   - reader without extended-length APDUs: CKR_DEVICE_ERROR, kind
//     ErrInsNotSupported (errors.Is(err, ErrExtendedAPDUNotSupported));
//     fall back to ReadDGS with the PIN, or use another reader.
//
// Requires libopencie-pkcs11 1.3.0.
func ReadDGSCan(can string) (*DataGroups, error) {
	cCan := C.CString(can)
	defer C.free(unsafe.Pointer(cCan))

	return readDGs(func(mrz *C.char, mrzLen *C.size_t, photo *C.uchar, photoLen *C.size_t) C.CK_RV {
		return C.cie_read_dgs_can(cCan, mrz, mrzLen, photo, photoLen)
	})
}

// ReadDGS reads DG1 (MRZ) and DG2 (portrait) in a single session, PIN based.
// It is the fallback for readers that cannot carry the extended-length APDUs
// ReadDGSCan needs (see ErrExtendedAPDUNotSupported). pin is the 8-digit
// numeric PIN; a wrong PIN decreases the card's retry counter.
//
// Failures are *CardError values, like for ReadDGSCan.
func ReadDGS(pin string) (*DataGroups, error) {
	cPin := C.CString(pin)
	defer freeSecret(cPin)

	return readDGs(func(mrz *C.char, mrzLen *C.size_t, photo *C.uchar, photoLen *C.size_t) C.CK_RV {
		return C.cie_read_dgs(cPin, mrz, mrzLen, photo, photoLen)
	})
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

// ReaderCount returns the number of currently attached PC/SC readers
// (virtual readers are not counted). It returns 0 if PC/SC is unavailable.
func ReaderCount() int {
	return int(C.cie_reader_count())
}

// ReaderWatch blocks until the reader count changes from currentCount, and
// returns the new reader count. It returns -1 if the PC/SC context could not
// be established or monitoring failed.
func ReaderWatch(currentCount int) int {
	if currentCount < math.MinInt32 || currentCount > math.MaxInt32 {
		return -1
	}
	return int(C.cie_reader_watch(C.int(currentCount)))
}

// ReaderName returns the name of the most useful attached reader: one that
// currently holds a card, else an empty contactless slot, else any other
// empty slot that is not the built-in Broadcom reader.
// It returns an empty string if no suitable reader is attached.
func ReaderName() (string, error) {
	const bufLen = 512
	buf := make([]byte, bufLen)
	// cie_reader_name returns 1 when a reader was found and its name is in
	// buf, 0 when none was found. It is NOT the length of the name.
	n := C.cie_reader_name((*C.char)(unsafe.Pointer(&buf[0])), C.int(bufLen))
	if n < 0 {
		return "", fmt.Errorf("cie_reader_name failed: %d", int(n))
	}
	if n == 0 {
		return "", nil
	}
	return cString(buf), nil
}

// cString returns the NUL-terminated string at the start of b.
func cString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Digest info
// ---------------------------------------------------------------------------

// OpenSSL NIDs accepted by MakeDigestInfo (NID_sha1, NID_sha256, NID_sha384,
// NID_sha512 from <openssl/obj_mac.h>).
const (
	NIDSHA1   = 65
	NIDSHA256 = 672
	NIDSHA384 = 673
	NIDSHA512 = 674
)

var (
	// ErrDigestInfoBufferTooSmall is no longer returned: MakeDigestInfo
	// builds the DigestInfo in Go with an exactly sized buffer.
	//
	// Deprecated: kept so existing code that compares against it still
	// compiles.
	ErrDigestInfoBufferTooSmall = errors.New("digest info buffer too small")
	// ErrUnsupportedDigestAlgorithm is returned by MakeDigestInfo for an
	// algid other than NIDSHA1, NIDSHA256, NIDSHA384 or NIDSHA512.
	ErrUnsupportedDigestAlgorithm = errors.New("cie: unsupported digest algorithm id")
	// ErrInvalidDigestLength is returned by MakeDigestInfo when the digest
	// length does not match the algorithm.
	ErrInvalidDigestLength = errors.New("cie: digest length does not match algorithm")
)

// digestInfoPrefix returns the DER DigestInfo prefix (RFC 8017, section 9.2,
// note 1) and the digest size of one of the supported NIDs.
func digestInfoPrefix(algid int) (prefix []byte, size int, ok bool) {
	switch algid {
	case NIDSHA1:
		return []byte{
			0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
			0x05, 0x00, 0x04, 0x14,
		}, 20, true
	case NIDSHA256:
		return []byte{
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
			0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
		}, 32, true
	case NIDSHA384:
		return []byte{
			0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
			0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
		}, 48, true
	case NIDSHA512:
		return []byte{
			0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
			0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
		}, 64, true
	}
	return nil, 0, false
}

// checkDigestArgs validates the arguments of MakeDigestInfo.
func checkDigestArgs(algid int, digest []byte) error {
	_, want, ok := digestInfoPrefix(algid)
	if !ok {
		return fmt.Errorf("%w: %d", ErrUnsupportedDigestAlgorithm, algid)
	}
	if len(digest) != want {
		return fmt.Errorf("%w: got %d bytes, want %d for NID %d", ErrInvalidDigestLength, len(digest), want, algid)
	}
	return nil
}

// MakeDigestInfo builds an ASN.1 DigestInfo structure for the given digest
// algorithm identifier (algid) and digest bytes. algid is an OpenSSL NID:
// NIDSHA1 (65), NIDSHA256 (672), NIDSHA384 (673) or NIDSHA512 (674), the
// same set make_digest_info supports. The returned slice contains the
// DER-encoded DigestInfo suitable for use with PKCS#11 raw RSA signing.
//
// The encoding is done in Go, byte for byte what libopencie-pkcs11's
// make_digest_info produces: the Linux release binaries of the library
// (x86_64 and aarch64, including 1.3.0) do not export that symbol even
// though the header and the linker version script list it, so binding it
// through cgo would make every program that imports this package fail to
// link. Unlike the C function, the digest length is checked against the
// algorithm instead of producing a malformed DigestInfo.
func MakeDigestInfo(algid int, digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("digest is empty")
	}
	if err := checkDigestArgs(algid, digest); err != nil {
		return nil, err
	}
	prefix, _, _ := digestInfoPrefix(algid)
	out := make([]byte, 0, len(prefix)+len(digest))
	out = append(out, prefix...)
	return append(out, digest...), nil
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

// ClassifySW classifies an ISO 7816 status word into a semantic error kind.
// This is a pure function; no card is required.
func ClassifySW(sw uint16) ErrorKind {
	return ErrorKind(C.cie_classify_sw(C.uint16_t(sw)))
}

// LastError returns the most recent error from a failed cie_* call on the
// calling OS thread. It returns the semantic error kind and the raw ISO 7816
// status word (or 0 if the failure carried no status word).
//
// A successful cie_* call resets the recorded error to ErrNone/0.
//
// WARNING: In Go, a goroutine can be rescheduled onto a different OS thread
// between calls. If your code calls a card operation followed by LastError(),
// you MUST lock the OS thread around both calls using runtime.LockOSThread()
// to ensure they execute on the same thread, else LastError() may report a
// stale or unrelated error. ReadDGS and ReadDGSCan do this for you and return
// the detail in a *CardError.
func LastError() (ErrorKind, uint16) {
	var cKind C.cie_error_kind
	var cSw C.uint16_t
	_ = C.cie_last_error(&cKind, &cSw)
	return ErrorKind(cKind), uint16(cSw)
}
