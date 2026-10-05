// SPDX-License-Identifier: MPL-2.0

// Package pkcs11 provides cgo bindings for the standard PKCS#11 interface
// exposed by libopencie-pkcs11.
package pkcs11

/*
#cgo LDFLAGS: -lopencie-pkcs11

// Define PKCS#11 platform macros before including headers
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#ifdef _WIN32
#define CK_ENTRY __cdecl
#else
#define CK_ENTRY
#endif

// Structure packing: pkcs11.h asks for 1-byte packing on Windows only
// ("In a UNIX environment, you're on your own"). libopencie-pkcs11 is built
// with 1-byte packing on Windows (shared/src/pkcs11/cryptoki.h) and with the
// natural ABI everywhere else. Forcing pack(1) on Linux/macOS shifts the
// fields of CK_INFO (sizeof 76 instead of 88: flags, libraryDescription and
// libraryVersion read from the wrong offsets and C_GetInfo overruns the
// buffer) and shortens CK_SLOT_INFO and CK_TOKEN_INFO by 4 bytes.
#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pkcs11/pkcs11.h>

#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif

// Layout guard (LP64 Unix, natural alignment): the library fills these
// structures with the natural ABI. Re-introducing pack(1) there would change
// sizeof(CK_INFO) to 76 and fail the build instead of corrupting memory.
#if !defined(_WIN32) && defined(__LP64__)
_Static_assert(sizeof(CK_INFO) == 88, "CK_INFO is not naturally aligned");
_Static_assert(offsetof(CK_INFO, flags) == 40, "CK_INFO.flags offset");
_Static_assert(sizeof(CK_SLOT_INFO) == 112, "CK_SLOT_INFO is not naturally aligned");
_Static_assert(sizeof(CK_TOKEN_INFO) == 208, "CK_TOKEN_INFO is not naturally aligned");
#endif

// Helper to create CK_C_INITIALIZE_ARGS with flags
static CK_C_INITIALIZE_ARGS* make_init_args(CK_FLAGS flags) {
	CK_C_INITIALIZE_ARGS* args = calloc(1, sizeof(CK_C_INITIALIZE_ARGS));
	args->flags = flags;
	return args;
}
*/
import "C"
import (
	"fmt"
	"strings"
	"unsafe"
)

// RV is the PKCS#11 return value type (CK_RV).
type RV C.CK_RV

// Error implements the error interface for RV.
func (r RV) Error() string {
	return fmt.Sprintf("CKR 0x%08X", uint64(r))
}

// Common PKCS#11 return codes
const (
	CKR_OK                           = RV(0x00000000)
	CKR_HOST_MEMORY                  = RV(0x00000002)
	CKR_GENERAL_ERROR                = RV(0x00000005)
	CKR_FUNCTION_FAILED              = RV(0x00000006)
	CKR_ARGUMENTS_BAD                = RV(0x00000007)
	CKR_ATTRIBUTE_TYPE_INVALID       = RV(0x00000012)
	CKR_DEVICE_ERROR                 = RV(0x00000030)
	CKR_FUNCTION_NOT_SUPPORTED       = RV(0x00000054)
	CKR_PIN_INCORRECT                = RV(0x000000A0)
	CKR_PIN_INVALID                  = RV(0x000000A1)
	CKR_PIN_LEN_RANGE                = RV(0x000000A2)
	CKR_PIN_LOCKED                   = RV(0x000000A4)
	CKR_SESSION_HANDLE_INVALID       = RV(0x000000B3)
	CKR_TOKEN_NOT_PRESENT            = RV(0x000000E0)
	CKR_TOKEN_NOT_RECOGNIZED         = RV(0x000000E1)
	CKR_USER_NOT_LOGGED_IN           = RV(0x00000101)
	CKR_BUFFER_TOO_SMALL             = RV(0x00000150)
	CKR_CRYPTOKI_NOT_INITIALIZED     = RV(0x00000190)
	CKR_CRYPTOKI_ALREADY_INITIALIZED = RV(0x00000191)
)

// Layout of the C structs as seen by cgo; checked by the unit tests.
var (
	ckInfoSize      = uintptr(C.sizeof_CK_INFO)
	ckInfoFlags     = unsafe.Offsetof(C.CK_INFO{}.flags)
	ckInfoLibDesc   = unsafe.Offsetof(C.CK_INFO{}.libraryDescription)
	ckInfoLibVer    = unsafe.Offsetof(C.CK_INFO{}.libraryVersion)
	ckSlotInfoSize  = uintptr(C.sizeof_CK_SLOT_INFO)
	ckTokenInfoSize = uintptr(C.sizeof_CK_TOKEN_INFO)
	ckAttributeSize = uintptr(C.sizeof_CK_ATTRIBUTE)
	ckULongSize     = uintptr(C.sizeof_CK_ULONG)
)

// trimPadded converts one of the fixed-size, blank-padded character fields of
// the PKCS#11 info structures (CK_INFO.manufacturerID, CK_TOKEN_INFO.label,
// ...) to a string. PKCS#11 pads these fields with spaces and does not
// NUL-terminate them: reading them as C strings runs past the end of the
// field. Trailing spaces and NULs are removed.
func trimPadded(b []byte) string {
	return strings.TrimRight(string(b), " \x00")
}

// field copies a fixed-size info field out of C memory. p must point to the
// first byte of an array of n bytes.
func field(p unsafe.Pointer, n int) string {
	return trimPadded(C.GoBytes(p, C.int(n)))
}

// bytePtr returns a pointer to the first byte of b, or nil if b is empty
// (&b[0] would panic).
func bytePtr(b []byte) *C.CK_BYTE {
	if len(b) == 0 {
		return nil
	}
	return (*C.CK_BYTE)(unsafe.Pointer(&b[0]))
}

// newMechanism converts m to a C CK_MECHANISM. The parameter is copied to C
// memory: a Go pointer stored in a struct handed to C violates the cgo
// pointer-passing rules. Call the returned function to release the copy.
func newMechanism(m Mechanism) (C.CK_MECHANISM, func()) {
	cMech := C.CK_MECHANISM{mechanism: m.Type}
	if len(m.Parameter) == 0 {
		return cMech, func() {}
	}
	p := C.CBytes(m.Parameter)
	cMech.pParameter = C.CK_VOID_PTR(p)
	cMech.ulParameterLen = C.CK_ULONG(len(m.Parameter))
	return cMech, func() { C.free(p) }
}

// cTemplate is a CK_ATTRIBUTE array allocated in C memory together with C
// copies of the attribute values. PKCS#11 templates hold pointers; keeping
// both the array and its values in C memory satisfies the cgo rule that Go
// memory passed to C must not contain Go pointers.
type cTemplate struct {
	attrs *C.CK_ATTRIBUTE // nil for an empty template
	n     C.CK_ULONG
	bufs  []unsafe.Pointer
}

func newCTemplate(t []Attribute) *cTemplate {
	c := &cTemplate{n: C.CK_ULONG(len(t))}
	if len(t) == 0 {
		return c
	}
	c.attrs = (*C.CK_ATTRIBUTE)(C.calloc(C.size_t(len(t)), C.sizeof_CK_ATTRIBUTE))
	attrs := c.slice()
	for i, a := range t {
		attrs[i]._type = a.Type
		if len(a.Value) > 0 {
			p := C.CBytes(a.Value)
			c.bufs = append(c.bufs, p)
			attrs[i].pValue = C.CK_VOID_PTR(p)
			attrs[i].ulValueLen = C.CK_ULONG(len(a.Value))
		}
	}
	return c
}

// slice returns the C array as a Go slice (nil for an empty template).
func (c *cTemplate) slice() []C.CK_ATTRIBUTE {
	if c.attrs == nil {
		return nil
	}
	return unsafe.Slice(c.attrs, int(c.n))
}

// alloc returns a zeroed C buffer of n bytes that is released by free.
func (c *cTemplate) alloc(n C.CK_ULONG) C.CK_VOID_PTR {
	p := C.calloc(1, C.size_t(n))
	c.bufs = append(c.bufs, p)
	return C.CK_VOID_PTR(p)
}

func (c *cTemplate) free() {
	for _, p := range c.bufs {
		C.free(p)
	}
	c.bufs = nil
	if c.attrs != nil {
		C.free(unsafe.Pointer(c.attrs))
		c.attrs = nil
	}
}

// SessionHandle represents a PKCS#11 session handle.
type SessionHandle C.CK_SESSION_HANDLE

// ObjectHandle represents a PKCS#11 object handle.
type ObjectHandle C.CK_OBJECT_HANDLE

// SlotID represents a PKCS#11 slot identifier.
type SlotID C.CK_SLOT_ID

// Flags represents PKCS#11 flags.
type Flags C.CK_FLAGS

// UserType represents the type of user (SO, normal user, context-specific).
type UserType C.CK_USER_TYPE

const (
	CKU_SO               = UserType(0)
	CKU_USER             = UserType(1)
	CKU_CONTEXT_SPECIFIC = UserType(2)
)

// SessionFlags
const (
	CKF_SERIAL_SESSION = Flags(0x00000004)
	CKF_RW_SESSION     = Flags(0x00000002)
)

// Mechanism represents a PKCS#11 mechanism.
type Mechanism struct {
	Type      C.CK_MECHANISM_TYPE
	Parameter []byte
}

// Attribute represents a PKCS#11 attribute.
type Attribute struct {
	Type  C.CK_ATTRIBUTE_TYPE
	Value []byte
}

// Info represents CK_INFO.
type Info struct {
	CryptokiVersion    [2]byte
	ManufacturerID     string
	Flags              Flags
	LibraryDescription string
	LibraryVersion     [2]byte
}

// SlotInfo represents CK_SLOT_INFO.
type SlotInfo struct {
	SlotDescription string
	ManufacturerID  string
	Flags           Flags
	HardwareVersion [2]byte
	FirmwareVersion [2]byte
}

// TokenInfo represents CK_TOKEN_INFO.
type TokenInfo struct {
	Label              string
	ManufacturerID     string
	Model              string
	SerialNumber       string
	Flags              Flags
	MaxSessionCount    uint64
	SessionCount       uint64
	MaxRwSessionCount  uint64
	RwSessionCount     uint64
	MaxPinLen          uint64
	MinPinLen          uint64
	TotalPublicMemory  uint64
	FreePublicMemory   uint64
	TotalPrivateMemory uint64
	FreePrivateMemory  uint64
	HardwareVersion    [2]byte
	FirmwareVersion    [2]byte
	UTCTime            string
}

// SessionInfo represents CK_SESSION_INFO.
type SessionInfo struct {
	SlotID      SlotID
	State       C.CK_STATE
	Flags       Flags
	DeviceError C.CK_ULONG
}

// Initialize initializes the PKCS#11 library.
func Initialize() error {
	args := C.make_init_args(C.CKF_OS_LOCKING_OK)
	defer C.free(unsafe.Pointer(args))
	rv := C.C_Initialize(C.CK_VOID_PTR(unsafe.Pointer(args)))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// Finalize closes the PKCS#11 library.
func Finalize() error {
	rv := C.C_Finalize(nil)
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// GetInfo retrieves general PKCS#11 library information.
func GetInfo() (*Info, error) {
	var cInfo C.CK_INFO
	rv := C.C_GetInfo(&cInfo)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}
	info := &Info{
		CryptokiVersion:    [2]byte{byte(cInfo.cryptokiVersion.major), byte(cInfo.cryptokiVersion.minor)},
		ManufacturerID:     field(unsafe.Pointer(&cInfo.manufacturerID[0]), len(cInfo.manufacturerID)),
		Flags:              Flags(cInfo.flags),
		LibraryDescription: field(unsafe.Pointer(&cInfo.libraryDescription[0]), len(cInfo.libraryDescription)),
		LibraryVersion:     [2]byte{byte(cInfo.libraryVersion.major), byte(cInfo.libraryVersion.minor)},
	}
	return info, nil
}

// GetSlotList retrieves the list of available slots.
func GetSlotList(tokenPresent bool) ([]SlotID, error) {
	var count C.CK_ULONG
	var present C.CK_BBOOL
	if tokenPresent {
		present = C.CK_TRUE
	} else {
		present = C.CK_FALSE
	}

	// First call to get count
	rv := C.C_GetSlotList(present, nil, &count)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	if count == 0 {
		return []SlotID{}, nil
	}

	// Second call to get slots
	slots := make([]C.CK_SLOT_ID, count)
	rv = C.C_GetSlotList(present, &slots[0], &count)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	result := make([]SlotID, count)
	for i := range result {
		result[i] = SlotID(slots[i])
	}
	return result, nil
}

// GetSlotInfo retrieves information about a specific slot.
func GetSlotInfo(slotID SlotID) (*SlotInfo, error) {
	var cInfo C.CK_SLOT_INFO
	rv := C.C_GetSlotInfo(C.CK_SLOT_ID(slotID), &cInfo)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}
	info := &SlotInfo{
		SlotDescription: field(unsafe.Pointer(&cInfo.slotDescription[0]), len(cInfo.slotDescription)),
		ManufacturerID:  field(unsafe.Pointer(&cInfo.manufacturerID[0]), len(cInfo.manufacturerID)),
		Flags:           Flags(cInfo.flags),
		HardwareVersion: [2]byte{byte(cInfo.hardwareVersion.major), byte(cInfo.hardwareVersion.minor)},
		FirmwareVersion: [2]byte{byte(cInfo.firmwareVersion.major), byte(cInfo.firmwareVersion.minor)},
	}
	return info, nil
}

// GetTokenInfo retrieves information about a token in a slot.
func GetTokenInfo(slotID SlotID) (*TokenInfo, error) {
	var cInfo C.CK_TOKEN_INFO
	rv := C.C_GetTokenInfo(C.CK_SLOT_ID(slotID), &cInfo)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}
	info := &TokenInfo{
		Label:              field(unsafe.Pointer(&cInfo.label[0]), len(cInfo.label)),
		ManufacturerID:     field(unsafe.Pointer(&cInfo.manufacturerID[0]), len(cInfo.manufacturerID)),
		Model:              field(unsafe.Pointer(&cInfo.model[0]), len(cInfo.model)),
		SerialNumber:       field(unsafe.Pointer(&cInfo.serialNumber[0]), len(cInfo.serialNumber)),
		Flags:              Flags(cInfo.flags),
		MaxSessionCount:    uint64(cInfo.ulMaxSessionCount),
		SessionCount:       uint64(cInfo.ulSessionCount),
		MaxRwSessionCount:  uint64(cInfo.ulMaxRwSessionCount),
		RwSessionCount:     uint64(cInfo.ulRwSessionCount),
		MaxPinLen:          uint64(cInfo.ulMaxPinLen),
		MinPinLen:          uint64(cInfo.ulMinPinLen),
		TotalPublicMemory:  uint64(cInfo.ulTotalPublicMemory),
		FreePublicMemory:   uint64(cInfo.ulFreePublicMemory),
		TotalPrivateMemory: uint64(cInfo.ulTotalPrivateMemory),
		FreePrivateMemory:  uint64(cInfo.ulFreePrivateMemory),
		HardwareVersion:    [2]byte{byte(cInfo.hardwareVersion.major), byte(cInfo.hardwareVersion.minor)},
		FirmwareVersion:    [2]byte{byte(cInfo.firmwareVersion.major), byte(cInfo.firmwareVersion.minor)},
		UTCTime:            field(unsafe.Pointer(&cInfo.utcTime[0]), len(cInfo.utcTime)),
	}
	return info, nil
}

// OpenSession opens a session on the specified slot.
func OpenSession(slotID SlotID, flags Flags) (SessionHandle, error) {
	var session C.CK_SESSION_HANDLE
	rv := C.C_OpenSession(C.CK_SLOT_ID(slotID), C.CK_FLAGS(flags), nil, nil, &session)
	if rv != C.CKR_OK {
		return 0, RV(rv)
	}
	return SessionHandle(session), nil
}

// CloseSession closes a session.
func CloseSession(session SessionHandle) error {
	rv := C.C_CloseSession(C.CK_SESSION_HANDLE(session))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// CloseAllSessions closes all sessions on a slot.
func CloseAllSessions(slotID SlotID) error {
	rv := C.C_CloseAllSessions(C.CK_SLOT_ID(slotID))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// GetSessionInfo retrieves session information.
func GetSessionInfo(session SessionHandle) (*SessionInfo, error) {
	var cInfo C.CK_SESSION_INFO
	rv := C.C_GetSessionInfo(C.CK_SESSION_HANDLE(session), &cInfo)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}
	info := &SessionInfo{
		SlotID:      SlotID(cInfo.slotID),
		State:       cInfo.state,
		Flags:       Flags(cInfo.flags),
		DeviceError: cInfo.ulDeviceError,
	}
	return info, nil
}

// Login logs a user into a session.
func Login(session SessionHandle, userType UserType, pin string) error {
	cPin := C.CString(pin)
	defer func() {
		// Wipe the C copy of the PIN before releasing it.
		C.memset(unsafe.Pointer(cPin), 0, C.strlen(cPin))
		C.free(unsafe.Pointer(cPin))
	}()
	rv := C.C_Login(C.CK_SESSION_HANDLE(session), C.CK_USER_TYPE(userType),
		(*C.CK_UTF8CHAR)(unsafe.Pointer(cPin)), C.CK_ULONG(len(pin)))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// Logout logs out from a session.
func Logout(session SessionHandle) error {
	rv := C.C_Logout(C.CK_SESSION_HANDLE(session))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// FindObjectsInit initializes an object search.
func FindObjectsInit(session SessionHandle, template []Attribute) error {
	tpl := newCTemplate(template)
	defer tpl.free()
	rv := C.C_FindObjectsInit(C.CK_SESSION_HANDLE(session), tpl.attrs, tpl.n)
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// FindObjects continues an object search. It returns at most max handles;
// an empty slice means the search is exhausted.
func FindObjects(session SessionHandle, max int) ([]ObjectHandle, error) {
	if max < 0 {
		return nil, CKR_ARGUMENTS_BAD
	}
	if max == 0 {
		return []ObjectHandle{}, nil
	}
	objects := make([]C.CK_OBJECT_HANDLE, max)
	var count C.CK_ULONG
	rv := C.C_FindObjects(C.CK_SESSION_HANDLE(session), &objects[0], C.CK_ULONG(max), &count)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}
	if int(count) > max {
		return nil, CKR_GENERAL_ERROR
	}
	result := make([]ObjectHandle, count)
	for i := range result {
		result[i] = ObjectHandle(objects[i])
	}
	return result, nil
}

// FindObjectsFinal terminates an object search.
func FindObjectsFinal(session SessionHandle) error {
	rv := C.C_FindObjectsFinal(C.CK_SESSION_HANDLE(session))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// GetAttributeValue retrieves attribute values from an object. The Value of
// the requested attributes the object does not have (or that are sensitive)
// is left empty.
func GetAttributeValue(session SessionHandle, object ObjectHandle, template []Attribute) ([]Attribute, error) {
	result := make([]Attribute, len(template))
	if len(template) == 0 {
		return result, nil
	}

	// Only the types are sent: the first call reports the value sizes.
	query := make([]Attribute, len(template))
	for i, attr := range template {
		query[i].Type = attr.Type
	}
	tpl := newCTemplate(query)
	defer tpl.free()
	attrs := tpl.slice()

	rv := C.C_GetAttributeValue(C.CK_SESSION_HANDLE(session), C.CK_OBJECT_HANDLE(object), tpl.attrs, tpl.n)
	if rv != C.CKR_OK && rv != C.CKR_ATTRIBUTE_TYPE_INVALID {
		return nil, RV(rv)
	}

	// Allocate C buffers of the reported sizes and fetch the values. The
	// buffers must live in C memory: the template is read by C and a Go
	// pointer stored in it would violate the cgo pointer-passing rules.
	for i := range attrs {
		n := attrs[i].ulValueLen
		if n == 0 || n == C.CK_UNAVAILABLE_INFORMATION {
			attrs[i].ulValueLen = 0
			continue
		}
		attrs[i].pValue = tpl.alloc(n)
	}

	rv = C.C_GetAttributeValue(C.CK_SESSION_HANDLE(session), C.CK_OBJECT_HANDLE(object), tpl.attrs, tpl.n)
	if rv != C.CKR_OK && rv != C.CKR_ATTRIBUTE_TYPE_INVALID {
		return nil, RV(rv)
	}

	for i := range attrs {
		result[i].Type = attrs[i]._type
		n := attrs[i].ulValueLen
		if n > 0 && n != C.CK_UNAVAILABLE_INFORMATION && attrs[i].pValue != nil {
			result[i].Value = C.GoBytes(unsafe.Pointer(attrs[i].pValue), C.int(n))
		}
	}

	return result, nil
}

// SetAttributeValue sets attribute values on an object.
func SetAttributeValue(session SessionHandle, object ObjectHandle, template []Attribute) error {
	tpl := newCTemplate(template)
	defer tpl.free()
	rv := C.C_SetAttributeValue(C.CK_SESSION_HANDLE(session), C.CK_OBJECT_HANDLE(object),
		tpl.attrs, tpl.n)
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// CreateObject creates a new object.
func CreateObject(session SessionHandle, template []Attribute) (ObjectHandle, error) {
	tpl := newCTemplate(template)
	defer tpl.free()
	var object C.CK_OBJECT_HANDLE
	rv := C.C_CreateObject(C.CK_SESSION_HANDLE(session), tpl.attrs, tpl.n, &object)
	if rv != C.CKR_OK {
		return 0, RV(rv)
	}
	return ObjectHandle(object), nil
}

// DestroyObject destroys an object.
func DestroyObject(session SessionHandle, object ObjectHandle) error {
	rv := C.C_DestroyObject(C.CK_SESSION_HANDLE(session), C.CK_OBJECT_HANDLE(object))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// EncryptInit initializes an encryption operation.
func EncryptInit(session SessionHandle, mechanism Mechanism, key ObjectHandle) error {
	cMech, freeMech := newMechanism(mechanism)
	defer freeMech()
	rv := C.C_EncryptInit(C.CK_SESSION_HANDLE(session), &cMech, C.CK_OBJECT_HANDLE(key))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// Encrypt encrypts data in a single operation.
func Encrypt(session SessionHandle, plaintext []byte) ([]byte, error) {
	var cipherLen C.CK_ULONG
	// First call to get length
	rv := C.C_Encrypt(C.CK_SESSION_HANDLE(session),
		bytePtr(plaintext), C.CK_ULONG(len(plaintext)),
		nil, &cipherLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	ciphertext := make([]byte, cipherLen)
	rv = C.C_Encrypt(C.CK_SESSION_HANDLE(session),
		bytePtr(plaintext), C.CK_ULONG(len(plaintext)),
		bytePtr(ciphertext), &cipherLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	return ciphertext[:cipherLen], nil
}

// DecryptInit initializes a decryption operation.
func DecryptInit(session SessionHandle, mechanism Mechanism, key ObjectHandle) error {
	cMech, freeMech := newMechanism(mechanism)
	defer freeMech()
	rv := C.C_DecryptInit(C.CK_SESSION_HANDLE(session), &cMech, C.CK_OBJECT_HANDLE(key))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// Decrypt decrypts data in a single operation.
func Decrypt(session SessionHandle, ciphertext []byte) ([]byte, error) {
	var plainLen C.CK_ULONG
	// First call to get length
	rv := C.C_Decrypt(C.CK_SESSION_HANDLE(session),
		bytePtr(ciphertext), C.CK_ULONG(len(ciphertext)),
		nil, &plainLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	plaintext := make([]byte, plainLen)
	rv = C.C_Decrypt(C.CK_SESSION_HANDLE(session),
		bytePtr(ciphertext), C.CK_ULONG(len(ciphertext)),
		bytePtr(plaintext), &plainLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	return plaintext[:plainLen], nil
}

// SignInit initializes a signing operation.
func SignInit(session SessionHandle, mechanism Mechanism, key ObjectHandle) error {
	cMech, freeMech := newMechanism(mechanism)
	defer freeMech()
	rv := C.C_SignInit(C.CK_SESSION_HANDLE(session), &cMech, C.CK_OBJECT_HANDLE(key))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// Sign signs data in a single operation.
func Sign(session SessionHandle, data []byte) ([]byte, error) {
	var sigLen C.CK_ULONG
	// First call to get length
	rv := C.C_Sign(C.CK_SESSION_HANDLE(session),
		bytePtr(data), C.CK_ULONG(len(data)),
		nil, &sigLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	signature := make([]byte, sigLen)
	rv = C.C_Sign(C.CK_SESSION_HANDLE(session),
		bytePtr(data), C.CK_ULONG(len(data)),
		bytePtr(signature), &sigLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	return signature[:sigLen], nil
}

// SignUpdate continues a multi-part signing operation.
func SignUpdate(session SessionHandle, data []byte) error {
	rv := C.C_SignUpdate(C.CK_SESSION_HANDLE(session),
		bytePtr(data), C.CK_ULONG(len(data)))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// SignFinal finishes a multi-part signing operation.
func SignFinal(session SessionHandle) ([]byte, error) {
	var sigLen C.CK_ULONG
	// First call to get length
	rv := C.C_SignFinal(C.CK_SESSION_HANDLE(session), nil, &sigLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	signature := make([]byte, sigLen)
	rv = C.C_SignFinal(C.CK_SESSION_HANDLE(session),
		bytePtr(signature), &sigLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	return signature[:sigLen], nil
}

// VerifyInit initializes a verification operation.
func VerifyInit(session SessionHandle, mechanism Mechanism, key ObjectHandle) error {
	cMech, freeMech := newMechanism(mechanism)
	defer freeMech()
	rv := C.C_VerifyInit(C.CK_SESSION_HANDLE(session), &cMech, C.CK_OBJECT_HANDLE(key))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// Verify verifies a signature in a single operation.
func Verify(session SessionHandle, data []byte, signature []byte) error {
	rv := C.C_Verify(C.CK_SESSION_HANDLE(session),
		bytePtr(data), C.CK_ULONG(len(data)),
		bytePtr(signature), C.CK_ULONG(len(signature)))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// DigestInit initializes a digest operation.
func DigestInit(session SessionHandle, mechanism Mechanism) error {
	cMech, freeMech := newMechanism(mechanism)
	defer freeMech()
	rv := C.C_DigestInit(C.CK_SESSION_HANDLE(session), &cMech)
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// Digest digests data in a single operation.
func Digest(session SessionHandle, data []byte) ([]byte, error) {
	var digestLen C.CK_ULONG
	// First call to get length
	rv := C.C_Digest(C.CK_SESSION_HANDLE(session),
		bytePtr(data), C.CK_ULONG(len(data)),
		nil, &digestLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	digest := make([]byte, digestLen)
	rv = C.C_Digest(C.CK_SESSION_HANDLE(session),
		bytePtr(data), C.CK_ULONG(len(data)),
		bytePtr(digest), &digestLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	return digest[:digestLen], nil
}

// DigestUpdate continues a multi-part digest operation.
func DigestUpdate(session SessionHandle, data []byte) error {
	rv := C.C_DigestUpdate(C.CK_SESSION_HANDLE(session),
		bytePtr(data), C.CK_ULONG(len(data)))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// DigestFinal finishes a multi-part digest operation.
func DigestFinal(session SessionHandle) ([]byte, error) {
	var digestLen C.CK_ULONG
	// First call to get length
	rv := C.C_DigestFinal(C.CK_SESSION_HANDLE(session), nil, &digestLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	digest := make([]byte, digestLen)
	rv = C.C_DigestFinal(C.CK_SESSION_HANDLE(session),
		bytePtr(digest), &digestLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	return digest[:digestLen], nil
}

// GenerateKey generates a secret key.
func GenerateKey(session SessionHandle, mechanism Mechanism, template []Attribute) (ObjectHandle, error) {
	cMech, freeMech := newMechanism(mechanism)
	defer freeMech()

	tpl := newCTemplate(template)
	defer tpl.free()

	var key C.CK_OBJECT_HANDLE
	rv := C.C_GenerateKey(C.CK_SESSION_HANDLE(session), &cMech, tpl.attrs, tpl.n, &key)
	if rv != C.CKR_OK {
		return 0, RV(rv)
	}
	return ObjectHandle(key), nil
}

// GenerateKeyPair generates a public/private key pair.
func GenerateKeyPair(session SessionHandle, mechanism Mechanism, publicTemplate, privateTemplate []Attribute) (ObjectHandle, ObjectHandle, error) {
	cMech, freeMech := newMechanism(mechanism)
	defer freeMech()

	pubTpl := newCTemplate(publicTemplate)
	defer pubTpl.free()

	privTpl := newCTemplate(privateTemplate)
	defer privTpl.free()

	var pubKey, privKey C.CK_OBJECT_HANDLE
	rv := C.C_GenerateKeyPair(C.CK_SESSION_HANDLE(session), &cMech,
		pubTpl.attrs, pubTpl.n,
		privTpl.attrs, privTpl.n,
		&pubKey, &privKey)
	if rv != C.CKR_OK {
		return 0, 0, RV(rv)
	}
	return ObjectHandle(pubKey), ObjectHandle(privKey), nil
}

// SeedRandom seeds the random number generator.
func SeedRandom(session SessionHandle, seed []byte) error {
	rv := C.C_SeedRandom(C.CK_SESSION_HANDLE(session),
		bytePtr(seed), C.CK_ULONG(len(seed)))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// GenerateRandom generates random data.
func GenerateRandom(session SessionHandle, length int) ([]byte, error) {
	if length < 0 {
		return nil, CKR_ARGUMENTS_BAD
	}
	if length == 0 {
		return []byte{}, nil
	}
	random := make([]byte, length)
	rv := C.C_GenerateRandom(C.CK_SESSION_HANDLE(session),
		bytePtr(random), C.CK_ULONG(length))
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}
	return random, nil
}
