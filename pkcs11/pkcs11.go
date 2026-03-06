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

#pragma pack(push, cryptoki, 1)

#include <stdlib.h>
#include <string.h>
#include <pkcs11/pkcs11.h>

#pragma pack(pop, cryptoki)

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
	CKR_OK                     = RV(0x00000000)
	CKR_FUNCTION_NOT_SUPPORTED = RV(0x00000054)
	CKR_PIN_INCORRECT          = RV(0x000000A0)
	CKR_PIN_LOCKED             = RV(0x000000A4)
	CKR_SESSION_HANDLE_INVALID = RV(0x000000B3)
	CKR_USER_NOT_LOGGED_IN     = RV(0x00000101)
)

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
		ManufacturerID:     C.GoString((*C.char)(unsafe.Pointer(&cInfo.manufacturerID[0]))),
		// Flags field is not accessible due to struct alignment issues with cgo
		Flags:              0,
		LibraryDescription: C.GoString((*C.char)(unsafe.Pointer(&cInfo.libraryDescription[0]))),
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
	for i := 0; i < int(count); i++ {
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
		SlotDescription: C.GoString((*C.char)(unsafe.Pointer(&cInfo.slotDescription[0]))),
		ManufacturerID:  C.GoString((*C.char)(unsafe.Pointer(&cInfo.manufacturerID[0]))),
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
		Label:              C.GoString((*C.char)(unsafe.Pointer(&cInfo.label[0]))),
		ManufacturerID:     C.GoString((*C.char)(unsafe.Pointer(&cInfo.manufacturerID[0]))),
		Model:              C.GoString((*C.char)(unsafe.Pointer(&cInfo.model[0]))),
		SerialNumber:       C.GoString((*C.char)(unsafe.Pointer(&cInfo.serialNumber[0]))),
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
		UTCTime:            C.GoString((*C.char)(unsafe.Pointer(&cInfo.utcTime[0]))),
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
	defer C.free(unsafe.Pointer(cPin))
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
	var cTemplate []C.CK_ATTRIBUTE
	if len(template) > 0 {
		cTemplate = make([]C.CK_ATTRIBUTE, len(template))
		for i, attr := range template {
			cTemplate[i]._type = attr.Type
			if len(attr.Value) > 0 {
				cTemplate[i].pValue = C.CK_VOID_PTR(unsafe.Pointer(&attr.Value[0]))
				cTemplate[i].ulValueLen = C.CK_ULONG(len(attr.Value))
			}
		}
	}
	var templatePtr *C.CK_ATTRIBUTE
	if len(cTemplate) > 0 {
		templatePtr = &cTemplate[0]
	}
	rv := C.C_FindObjectsInit(C.CK_SESSION_HANDLE(session), templatePtr, C.CK_ULONG(len(cTemplate)))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// FindObjects continues an object search.
func FindObjects(session SessionHandle, max int) ([]ObjectHandle, error) {
	objects := make([]C.CK_OBJECT_HANDLE, max)
	var count C.CK_ULONG
	rv := C.C_FindObjects(C.CK_SESSION_HANDLE(session), &objects[0], C.CK_ULONG(max), &count)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}
	result := make([]ObjectHandle, count)
	for i := 0; i < int(count); i++ {
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

// GetAttributeValue retrieves attribute values from an object.
func GetAttributeValue(session SessionHandle, object ObjectHandle, template []Attribute) ([]Attribute, error) {
	cTemplate := make([]C.CK_ATTRIBUTE, len(template))
	for i, attr := range template {
		cTemplate[i]._type = attr.Type
		cTemplate[i].pValue = nil
		cTemplate[i].ulValueLen = 0
	}

	// First call to get sizes
	rv := C.C_GetAttributeValue(C.CK_SESSION_HANDLE(session), C.CK_OBJECT_HANDLE(object),
		&cTemplate[0], C.CK_ULONG(len(cTemplate)))
	if rv != C.CKR_OK && rv != C.CKR_ATTRIBUTE_TYPE_INVALID {
		return nil, RV(rv)
	}

	// Allocate buffers and second call
	result := make([]Attribute, len(template))
	for i := range cTemplate {
		result[i].Type = cTemplate[i]._type
		if cTemplate[i].ulValueLen > 0 && cTemplate[i].ulValueLen != C.CK_UNAVAILABLE_INFORMATION {
			result[i].Value = make([]byte, cTemplate[i].ulValueLen)
			cTemplate[i].pValue = C.CK_VOID_PTR(unsafe.Pointer(&result[i].Value[0]))
		}
	}

	rv = C.C_GetAttributeValue(C.CK_SESSION_HANDLE(session), C.CK_OBJECT_HANDLE(object),
		&cTemplate[0], C.CK_ULONG(len(cTemplate)))
	if rv != C.CKR_OK && rv != C.CKR_ATTRIBUTE_TYPE_INVALID {
		return nil, RV(rv)
	}

	return result, nil
}

// SetAttributeValue sets attribute values on an object.
func SetAttributeValue(session SessionHandle, object ObjectHandle, template []Attribute) error {
	cTemplate := make([]C.CK_ATTRIBUTE, len(template))
	for i, attr := range template {
		cTemplate[i]._type = attr.Type
		if len(attr.Value) > 0 {
			cTemplate[i].pValue = C.CK_VOID_PTR(unsafe.Pointer(&attr.Value[0]))
			cTemplate[i].ulValueLen = C.CK_ULONG(len(attr.Value))
		}
	}
	rv := C.C_SetAttributeValue(C.CK_SESSION_HANDLE(session), C.CK_OBJECT_HANDLE(object),
		&cTemplate[0], C.CK_ULONG(len(cTemplate)))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// CreateObject creates a new object.
func CreateObject(session SessionHandle, template []Attribute) (ObjectHandle, error) {
	cTemplate := make([]C.CK_ATTRIBUTE, len(template))
	for i, attr := range template {
		cTemplate[i]._type = attr.Type
		if len(attr.Value) > 0 {
			cTemplate[i].pValue = C.CK_VOID_PTR(unsafe.Pointer(&attr.Value[0]))
			cTemplate[i].ulValueLen = C.CK_ULONG(len(attr.Value))
		}
	}
	var object C.CK_OBJECT_HANDLE
	rv := C.C_CreateObject(C.CK_SESSION_HANDLE(session), &cTemplate[0], C.CK_ULONG(len(cTemplate)), &object)
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
	cMech := C.CK_MECHANISM{
		mechanism: mechanism.Type,
	}
	if len(mechanism.Parameter) > 0 {
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(&mechanism.Parameter[0]))
		cMech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	}
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
		(*C.CK_BYTE)(unsafe.Pointer(&plaintext[0])), C.CK_ULONG(len(plaintext)),
		nil, &cipherLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	ciphertext := make([]byte, cipherLen)
	rv = C.C_Encrypt(C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(unsafe.Pointer(&plaintext[0])), C.CK_ULONG(len(plaintext)),
		(*C.CK_BYTE)(unsafe.Pointer(&ciphertext[0])), &cipherLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	return ciphertext[:cipherLen], nil
}

// DecryptInit initializes a decryption operation.
func DecryptInit(session SessionHandle, mechanism Mechanism, key ObjectHandle) error {
	cMech := C.CK_MECHANISM{
		mechanism: mechanism.Type,
	}
	if len(mechanism.Parameter) > 0 {
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(&mechanism.Parameter[0]))
		cMech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	}
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
		(*C.CK_BYTE)(unsafe.Pointer(&ciphertext[0])), C.CK_ULONG(len(ciphertext)),
		nil, &plainLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	plaintext := make([]byte, plainLen)
	rv = C.C_Decrypt(C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(unsafe.Pointer(&ciphertext[0])), C.CK_ULONG(len(ciphertext)),
		(*C.CK_BYTE)(unsafe.Pointer(&plaintext[0])), &plainLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	return plaintext[:plainLen], nil
}

// SignInit initializes a signing operation.
func SignInit(session SessionHandle, mechanism Mechanism, key ObjectHandle) error {
	cMech := C.CK_MECHANISM{
		mechanism: mechanism.Type,
	}
	if len(mechanism.Parameter) > 0 {
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(&mechanism.Parameter[0]))
		cMech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	}
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
		(*C.CK_BYTE)(unsafe.Pointer(&data[0])), C.CK_ULONG(len(data)),
		nil, &sigLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	signature := make([]byte, sigLen)
	rv = C.C_Sign(C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(unsafe.Pointer(&data[0])), C.CK_ULONG(len(data)),
		(*C.CK_BYTE)(unsafe.Pointer(&signature[0])), &sigLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	return signature[:sigLen], nil
}

// SignUpdate continues a multi-part signing operation.
func SignUpdate(session SessionHandle, data []byte) error {
	rv := C.C_SignUpdate(C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(unsafe.Pointer(&data[0])), C.CK_ULONG(len(data)))
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
		(*C.CK_BYTE)(unsafe.Pointer(&signature[0])), &sigLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	return signature[:sigLen], nil
}

// VerifyInit initializes a verification operation.
func VerifyInit(session SessionHandle, mechanism Mechanism, key ObjectHandle) error {
	cMech := C.CK_MECHANISM{
		mechanism: mechanism.Type,
	}
	if len(mechanism.Parameter) > 0 {
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(&mechanism.Parameter[0]))
		cMech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	}
	rv := C.C_VerifyInit(C.CK_SESSION_HANDLE(session), &cMech, C.CK_OBJECT_HANDLE(key))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// Verify verifies a signature in a single operation.
func Verify(session SessionHandle, data []byte, signature []byte) error {
	rv := C.C_Verify(C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(unsafe.Pointer(&data[0])), C.CK_ULONG(len(data)),
		(*C.CK_BYTE)(unsafe.Pointer(&signature[0])), C.CK_ULONG(len(signature)))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// DigestInit initializes a digest operation.
func DigestInit(session SessionHandle, mechanism Mechanism) error {
	cMech := C.CK_MECHANISM{
		mechanism: mechanism.Type,
	}
	if len(mechanism.Parameter) > 0 {
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(&mechanism.Parameter[0]))
		cMech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	}
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
		(*C.CK_BYTE)(unsafe.Pointer(&data[0])), C.CK_ULONG(len(data)),
		nil, &digestLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	digest := make([]byte, digestLen)
	rv = C.C_Digest(C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(unsafe.Pointer(&data[0])), C.CK_ULONG(len(data)),
		(*C.CK_BYTE)(unsafe.Pointer(&digest[0])), &digestLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	return digest[:digestLen], nil
}

// DigestUpdate continues a multi-part digest operation.
func DigestUpdate(session SessionHandle, data []byte) error {
	rv := C.C_DigestUpdate(C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(unsafe.Pointer(&data[0])), C.CK_ULONG(len(data)))
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
		(*C.CK_BYTE)(unsafe.Pointer(&digest[0])), &digestLen)
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}

	return digest[:digestLen], nil
}

// GenerateKey generates a secret key.
func GenerateKey(session SessionHandle, mechanism Mechanism, template []Attribute) (ObjectHandle, error) {
	cMech := C.CK_MECHANISM{
		mechanism: mechanism.Type,
	}
	if len(mechanism.Parameter) > 0 {
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(&mechanism.Parameter[0]))
		cMech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	}

	cTemplate := make([]C.CK_ATTRIBUTE, len(template))
	for i, attr := range template {
		cTemplate[i]._type = attr.Type
		if len(attr.Value) > 0 {
			cTemplate[i].pValue = C.CK_VOID_PTR(unsafe.Pointer(&attr.Value[0]))
			cTemplate[i].ulValueLen = C.CK_ULONG(len(attr.Value))
		}
	}

	var key C.CK_OBJECT_HANDLE
	rv := C.C_GenerateKey(C.CK_SESSION_HANDLE(session), &cMech, &cTemplate[0], C.CK_ULONG(len(cTemplate)), &key)
	if rv != C.CKR_OK {
		return 0, RV(rv)
	}
	return ObjectHandle(key), nil
}

// GenerateKeyPair generates a public/private key pair.
func GenerateKeyPair(session SessionHandle, mechanism Mechanism, publicTemplate, privateTemplate []Attribute) (ObjectHandle, ObjectHandle, error) {
	cMech := C.CK_MECHANISM{
		mechanism: mechanism.Type,
	}
	if len(mechanism.Parameter) > 0 {
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(&mechanism.Parameter[0]))
		cMech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	}

	cPublicTemplate := make([]C.CK_ATTRIBUTE, len(publicTemplate))
	for i, attr := range publicTemplate {
		cPublicTemplate[i]._type = attr.Type
		if len(attr.Value) > 0 {
			cPublicTemplate[i].pValue = C.CK_VOID_PTR(unsafe.Pointer(&attr.Value[0]))
			cPublicTemplate[i].ulValueLen = C.CK_ULONG(len(attr.Value))
		}
	}

	cPrivateTemplate := make([]C.CK_ATTRIBUTE, len(privateTemplate))
	for i, attr := range privateTemplate {
		cPrivateTemplate[i]._type = attr.Type
		if len(attr.Value) > 0 {
			cPrivateTemplate[i].pValue = C.CK_VOID_PTR(unsafe.Pointer(&attr.Value[0]))
			cPrivateTemplate[i].ulValueLen = C.CK_ULONG(len(attr.Value))
		}
	}

	var pubKey, privKey C.CK_OBJECT_HANDLE
	rv := C.C_GenerateKeyPair(C.CK_SESSION_HANDLE(session), &cMech,
		&cPublicTemplate[0], C.CK_ULONG(len(cPublicTemplate)),
		&cPrivateTemplate[0], C.CK_ULONG(len(cPrivateTemplate)),
		&pubKey, &privKey)
	if rv != C.CKR_OK {
		return 0, 0, RV(rv)
	}
	return ObjectHandle(pubKey), ObjectHandle(privKey), nil
}

// SeedRandom seeds the random number generator.
func SeedRandom(session SessionHandle, seed []byte) error {
	rv := C.C_SeedRandom(C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(unsafe.Pointer(&seed[0])), C.CK_ULONG(len(seed)))
	if rv != C.CKR_OK {
		return RV(rv)
	}
	return nil
}

// GenerateRandom generates random data.
func GenerateRandom(session SessionHandle, length int) ([]byte, error) {
	random := make([]byte, length)
	rv := C.C_GenerateRandom(C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(unsafe.Pointer(&random[0])), C.CK_ULONG(length))
	if rv != C.CKR_OK {
		return nil, RV(rv)
	}
	return random, nil
}
