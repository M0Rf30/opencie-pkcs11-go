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

// Note: Callback support is limited. For full callback functionality,
// a more complex cookie-based mechanism would be required.
// For now, callbacks can be passed as nil to C functions that accept NULL.
*/
import "C"
import (
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
	// CKR_OK indicates success
	CKR_OK = RV(0x00000000)
)

const (
	// MaxLen is the maximum length for strings in VerifyInfo
	MaxLen = 512
)

// ProgressCallback is called periodically during long operations.
// Note: Go callbacks cannot be directly passed to C. This is a placeholder type.
// Pass nil to functions that accept progress callbacks.
type ProgressCallback func(progress int, message string) error

// CompletedCallback is called once when enrolment finishes.
// Note: Go callbacks cannot be directly passed to C. This is a placeholder type.
// Pass nil to functions that accept completed callbacks.
type CompletedCallback func(pan, name, serial string) error

// SignCompletedCallback is called once when signing finishes.
// Note: Go callbacks cannot be directly passed to C. This is a placeholder type.
// Pass nil to functions that accept sign-completed callbacks.
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
// Note: Callbacks are not fully supported in this binding. Pass nil for both callbacks.
// attempts will be set to the remaining PIN attempts on error if non-nil.
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

	// Note: Passing NULL for callbacks. Full callback support would require
	// a cookie-based mechanism with //export functions.
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
// Note: progress callback is not supported; pass nil.
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
// Note: progress callback is not supported; pass nil.
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

// Sign signs a PDF file on behalf of the card identified by pan.
// sigType: signature type string (e.g., "PDF", "P7M")
// page: page index (0-based) for the signature widget
// x, y, w, h: position and size of the signature widget in points
// imagePath: path to an optional signature image; may be empty
// Note: callbacks are not supported; pass nil.
func Sign(inFile, sigType, pin, pan string, page int, x, y, w, h float32, imagePath, outFile string, progress ProgressCallback, signCompleted SignCompletedCallback) error {
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

	var cImagePath *C.char
	if imagePath != "" {
		cImagePath = C.CString(imagePath)
		defer C.free(unsafe.Pointer(cImagePath))
	}

	rv := C.cie_sign(cInFile, cType, cPin, cPan, C.int(page),
		C.float(x), C.float(y), C.float(w), C.float(h),
		cImagePath, cOutFile, nil, nil)

	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// Verify verifies a signed document.
// proxyAddr: HTTP proxy address; may be empty
// proxyPort: HTTP proxy port (0 = no proxy)
// usrPass: proxy username:password; may be empty
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

	if rv < 0 {
		return 0, RV(rv)
	}
	return int(rv), nil
}

// GetSignCount returns the number of signatures found by the last Verify call.
func GetSignCount() (int, error) {
	rv := C.cie_get_sign_count()
	if rv < 0 {
		return 0, RV(rv)
	}
	return int(rv), nil
}

// GetVerifyInfo retrieves signer information for the n-th signature found by the last Verify call.
// index: zero-based signature index
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
