// SPDX-License-Identifier: MPL-2.0

package pkcs11

// These tests need libopencie-pkcs11 at link/run time but no card and no
// reader: C_Initialize is never called, so the library never opens PC/SC.

import (
	"errors"
	"runtime"
	"testing"
	"unsafe"
)

func TestTrimPadded(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"OpenCIE                         ", "OpenCIE"},
		{"no padding", "no padding"},
		{"nul\x00\x00 \x00", "nul"},
		{"  leading kept", "  leading kept"},
		{"                ", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := trimPadded([]byte(c.in)); got != c.want {
			t.Errorf("trimPadded(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// A full field with no NUL and no padding must be returned whole, not
	// run past its end like a C string would.
	full := make([]byte, 32)
	for i := range full {
		full[i] = 'A'
	}
	if got := trimPadded(full); len(got) != 32 {
		t.Errorf("full field truncated to %d bytes", len(got))
	}
}

func TestStructLayout(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The Windows build uses 1-byte packing, like the library.
		if ckInfoSize != 76 {
			t.Errorf("sizeof(CK_INFO) = %d, want 76 (packed)", ckInfoSize)
		}
		return
	}
	if unsafe.Sizeof(uintptr(0)) == 8 {
		// Natural alignment, as the library builds it on LP64 Unix: with
		// pack(1) CK_INFO would be 76 bytes and its flags field would sit at
		// offset 34, so C_GetInfo wrote past the Go struct.
		want := map[string][2]uintptr{
			"sizeof(CK_INFO)":           {ckInfoSize, 88},
			"offsetof(CK_INFO.flags)":   {ckInfoFlags, 40},
			"offsetof(CK_INFO.libDesc)": {ckInfoLibDesc, 48},
			"offsetof(CK_INFO.libVer)":  {ckInfoLibVer, 80},
			"sizeof(CK_SLOT_INFO)":      {ckSlotInfoSize, 112},
			"sizeof(CK_TOKEN_INFO)":     {ckTokenInfoSize, 208},
			"sizeof(CK_ATTRIBUTE)":      {ckAttributeSize, 24},
			"sizeof(CK_ULONG)":          {ckULongSize, 8},
		}
		for name, v := range want {
			if v[0] != v[1] {
				t.Errorf("%s = %d, want %d", name, v[0], v[1])
			}
		}
	}
}

func TestBytePtrEmpty(t *testing.T) {
	if bytePtr(nil) != nil || bytePtr([]byte{}) != nil {
		t.Error("bytePtr of an empty slice must be nil")
	}
	b := []byte{1, 2}
	if bytePtr(b) == nil {
		t.Error("bytePtr of a non-empty slice is nil")
	}
}

func TestRVError(t *testing.T) {
	if got := CKR_PIN_INCORRECT.Error(); got != "CKR 0x000000A0" {
		t.Errorf("Error() = %q", got)
	}
}

func TestConstants(t *testing.T) {
	want := map[RV]uint64{
		CKR_OK:                           0x00,
		CKR_HOST_MEMORY:                  0x02,
		CKR_GENERAL_ERROR:                0x05,
		CKR_FUNCTION_FAILED:              0x06,
		CKR_ARGUMENTS_BAD:                0x07,
		CKR_ATTRIBUTE_TYPE_INVALID:       0x12,
		CKR_DEVICE_ERROR:                 0x30,
		CKR_FUNCTION_NOT_SUPPORTED:       0x54,
		CKR_PIN_INCORRECT:                0xA0,
		CKR_PIN_INVALID:                  0xA1,
		CKR_PIN_LEN_RANGE:                0xA2,
		CKR_PIN_LOCKED:                   0xA4,
		CKR_SESSION_HANDLE_INVALID:       0xB3,
		CKR_TOKEN_NOT_PRESENT:            0xE0,
		CKR_TOKEN_NOT_RECOGNIZED:         0xE1,
		CKR_USER_NOT_LOGGED_IN:           0x101,
		CKR_BUFFER_TOO_SMALL:             0x150,
		CKR_CRYPTOKI_NOT_INITIALIZED:     0x190,
		CKR_CRYPTOKI_ALREADY_INITIALIZED: 0x191,
	}
	for rv, v := range want {
		if uint64(rv) != v {
			t.Errorf("%v = %#x, want %#x", rv, uint64(rv), v)
		}
	}
}

// Before C_Initialize the library refuses everything; the bindings must map
// that to an RV instead of crashing (the previous packed CK_INFO overflowed).
func TestNotInitialized(t *testing.T) {
	var rv RV

	if info, err := GetInfo(); info != nil || !errors.As(err, &rv) || rv != CKR_CRYPTOKI_NOT_INITIALIZED {
		t.Errorf("GetInfo() = (%v, %v), want CKR_CRYPTOKI_NOT_INITIALIZED", info, err)
	}
	if _, err := GetSlotList(true); !errors.As(err, &rv) || rv != CKR_CRYPTOKI_NOT_INITIALIZED {
		t.Errorf("GetSlotList() = %v, want CKR_CRYPTOKI_NOT_INITIALIZED", err)
	}
	if _, err := GetSlotInfo(0); !errors.As(err, &rv) || rv != CKR_CRYPTOKI_NOT_INITIALIZED {
		t.Errorf("GetSlotInfo() = %v, want CKR_CRYPTOKI_NOT_INITIALIZED", err)
	}
	if _, err := GetTokenInfo(0); !errors.As(err, &rv) || rv != CKR_CRYPTOKI_NOT_INITIALIZED {
		t.Errorf("GetTokenInfo() = %v, want CKR_CRYPTOKI_NOT_INITIALIZED", err)
	}
	if _, err := OpenSession(0, CKF_SERIAL_SESSION); !errors.As(err, &rv) || rv != CKR_CRYPTOKI_NOT_INITIALIZED {
		t.Errorf("OpenSession() = %v, want CKR_CRYPTOKI_NOT_INITIALIZED", err)
	}
}

// Empty inputs used to panic on &slice[0]; they must reach the library (or be
// rejected) without a Go panic. A bogus session handle keeps every call
// harmless.
func TestEmptyInputsDoNotPanic(t *testing.T) {
	const s = SessionHandle(0xDEAD)
	mech := Mechanism{Type: 0x00000250} // CKM_SHA256: parameter-less

	calls := map[string]func(){
		"FindObjectsInit(nil)":   func() { _ = FindObjectsInit(s, nil) },
		"FindObjects(0)":         func() { _, _ = FindObjects(s, 0) },
		"FindObjects(-1)":        func() { _, _ = FindObjects(s, -1) },
		"GetAttributeValue(nil)": func() { _, _ = GetAttributeValue(s, 1, nil) },
		"SetAttributeValue(nil)": func() { _ = SetAttributeValue(s, 1, nil) },
		"CreateObject(nil)":      func() { _, _ = CreateObject(s, nil) },
		"GenerateKey(nil)":       func() { _, _ = GenerateKey(s, mech, nil) },
		"GenerateKeyPair(nil)":   func() { _, _, _ = GenerateKeyPair(s, mech, nil, nil) },
		"Encrypt(nil)":           func() { _, _ = Encrypt(s, nil) },
		"Decrypt(nil)":           func() { _, _ = Decrypt(s, nil) },
		"Sign(nil)":              func() { _, _ = Sign(s, nil) },
		"SignUpdate(nil)":        func() { _ = SignUpdate(s, nil) },
		"Verify(nil, nil)":       func() { _ = Verify(s, nil, nil) },
		"Digest(nil)":            func() { _, _ = Digest(s, nil) },
		"DigestUpdate(nil)":      func() { _ = DigestUpdate(s, nil) },
		"SeedRandom(nil)":        func() { _ = SeedRandom(s, nil) },
		"GenerateRandom(0)":      func() { _, _ = GenerateRandom(s, 0) },
		"GenerateRandom(-1)":     func() { _, _ = GenerateRandom(s, -1) },
		"DigestInit(param)":      func() { _ = DigestInit(s, Mechanism{Type: 0x250, Parameter: []byte{1, 2, 3}}) },
		"Login(empty PIN)":       func() { _ = Login(s, CKU_USER, "") },
		"FindObjectsInit(values)": func() {
			_ = FindObjectsInit(s, []Attribute{{Type: 0, Value: []byte{1, 2, 3}}, {Type: 1}})
		},
		"GetAttributeValue(values)": func() {
			_, _ = GetAttributeValue(s, 1, []Attribute{{Type: 0x11}, {Type: 0x101}})
		},
		"CreateObject(values)": func() {
			_, _ = CreateObject(s, []Attribute{{Type: 0, Value: []byte{9}}})
		},
		"GenerateKeyPair(values)": func() {
			_, _, _ = GenerateKeyPair(s, Mechanism{Type: 0x250, Parameter: []byte{1}},
				[]Attribute{{Type: 0, Value: []byte{1}}}, []Attribute{{Type: 1, Value: []byte{2}}})
		},
	}
	for name, f := range calls {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s panicked: %v", name, r)
				}
			}()
			f()
		}()
	}
}

func TestFindObjectsArgumentChecks(t *testing.T) {
	var rv RV
	if _, err := FindObjects(1, -1); !errors.As(err, &rv) || rv != CKR_ARGUMENTS_BAD {
		t.Errorf("FindObjects(-1) = %v", err)
	}
	if got, err := FindObjects(1, 0); err != nil || len(got) != 0 {
		t.Errorf("FindObjects(0) = (%v, %v)", got, err)
	}
	if _, err := GenerateRandom(1, -1); !errors.As(err, &rv) || rv != CKR_ARGUMENTS_BAD {
		t.Errorf("GenerateRandom(-1) = %v", err)
	}
	if got, err := GenerateRandom(1, 0); err != nil || len(got) != 0 {
		t.Errorf("GenerateRandom(0) = (%v, %v)", got, err)
	}
}
