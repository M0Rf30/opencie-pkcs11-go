// SPDX-License-Identifier: MPL-2.0

package cie

// These tests need libopencie-pkcs11 1.3.0 or newer at link/run time (the
// package links it through cgo) but no card and no reader: they cover the
// layout of the C structures, the classification of return codes, and the
// pure functions of the library.

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"
)

func TestVerifyInfoLayout(t *testing.T) {
	if MaxLen != 512 {
		t.Fatalf("MaxLen = %d, want 512", MaxLen)
	}
	if verifyInfoNameLen != 2*MaxLen {
		t.Errorf("sizeof(name) = %d, want %d", verifyInfoNameLen, 2*MaxLen)
	}
	const strings = 5 * 2 * MaxLen
	if verifyInfoCertRevocOffset != strings {
		t.Errorf("offsetof(CertRevocStatus) = %d, want %d", verifyInfoCertRevocOffset, strings)
	}
	if verifyInfoIsSignOffset != strings+4 {
		t.Errorf("offsetof(isSignValid) = %d, want %d", verifyInfoIsSignOffset, strings+4)
	}
	if verifyInfoIsCertOffset != strings+8 {
		t.Errorf("offsetof(isCertValid) = %d, want %d", verifyInfoIsCertOffset, strings+8)
	}
	if verifyInfoSize != strings+12 {
		t.Errorf("sizeof(verifyInfo_t) = %d, want %d", verifyInfoSize, strings+12)
	}
}

func TestRVWidth(t *testing.T) {
	// CK_RV is "unsigned long": 32-bit on Windows, pointer-sized elsewhere.
	want := unsafe.Sizeof(uintptr(0))
	if runtime.GOOS == "windows" {
		want = 4
	}
	if got := unsafe.Sizeof(RV(0)); got != want {
		t.Errorf("sizeof(RV) = %d, want %d", got, want)
	}
}

func TestErrorKindValues(t *testing.T) {
	want := map[ErrorKind]uint32{
		ErrNone:                 0,
		ErrWrongPin:             1,
		ErrPinBlocked:           2,
		ErrPinNotSet:            3,
		ErrSecurityNotSatisfied: 4,
		ErrFileNotFound:         5,
		ErrWrongParams:          6,
		ErrInsNotSupported:      7,
		ErrCardCommunication:    8,
		ErrUnknown:              9,
		ErrUnsupportedCard:      10,
		ErrWrongCan:             11,
	}
	for k, v := range want {
		if uint32(k) != v {
			t.Errorf("%v = %d, want %d", k, uint32(k), v)
		}
		if k.String() == "" {
			t.Errorf("kind %d has no name", v)
		}
	}
	if got := ErrorKind(99).String(); got != "ErrorKind(99)" {
		t.Errorf("unknown kind string = %q", got)
	}
}

func TestSignErrorCodes(t *testing.T) {
	if SignErrorBase != 0x84000000 {
		t.Fatalf("SignErrorBase = %#x", uint64(SignErrorBase))
	}
	if SignErrUnexpected != 0x84000001 || SignErrFileNotFound != 0x84000002 ||
		SignErrCertNotForSignature != 0x8400000D || SignErrTSLLoad != 0x84000014 ||
		SignErrTSA != 0x8400001E {
		t.Error("CIE_SIGN_ERROR_* constants do not match cie_sign_api.h")
	}
	if SignErrorBase <= maxSignCount {
		t.Error("sign errors must not look like signature counts")
	}
}

func TestClassifySignCount(t *testing.T) {
	// A negative status cast to CK_RV, in the width of the platform.
	zero := RV(0)
	neg2 := zero - 2

	cases := []struct {
		name    string
		rv, cnt RV
		want    int
		wantErr RV // 0: no error expected
	}{
		{"no signatures", 0, 0, 0, 0},
		{"one signature", 1, 1, 1, 0},
		{"three signatures", 3, 3, 3, 0},
		// A count above the old 0x1000 heuristic is still a count.
		{"many signatures", 0x2000, 0x2000, 0x2000, 0},
		{"file not found", SignErrFileNotFound, 0, 0, SignErrFileNotFound},
		{"invalid file", SignErrInvalidFile, 0, 0, SignErrInvalidFile},
		{"negative status", neg2, 0, 0, neg2},
		{"same error from both", SignErrUnexpected, SignErrUnexpected, 0, SignErrUnexpected},
		{"count differs", 2, 1, 0, 2},
		{"error but count says zero", 0x1000, 0, 0, 0x1000},
	}
	for _, c := range cases {
		got, err := classifySignCount(c.rv, c.cnt)
		if c.wantErr == 0 {
			if err != nil || got != c.want {
				t.Errorf("%s: got (%d, %v), want (%d, nil)", c.name, got, err, c.want)
			}
			continue
		}
		var rv RV
		if !errors.As(err, &rv) || rv != c.wantErr || got != 0 {
			t.Errorf("%s: got (%d, %v), want error %v", c.name, got, err, c.wantErr)
		}
	}
}

func TestRVError(t *testing.T) {
	if got := CKR_PIN_INCORRECT.Error(); got != "CIE CKR 0x000000A0 (CKR_PIN_INCORRECT)" {
		t.Errorf("Error() = %q", got)
	}
	if got := RV(0x12345678).Error(); got != "CIE CKR 0x12345678" {
		t.Errorf("Error() = %q", got)
	}
}

func TestClassifyReadError(t *testing.T) {
	cases := []struct {
		name        string
		rv          RV
		kind        ErrorKind
		sw          uint16
		wantCAN     bool
		wantExtAPDU bool
		wantNoPACE  bool
	}{
		{name: "wrong CAN", rv: CKR_PIN_INCORRECT, kind: ErrWrongCan, wantCAN: true},
		{name: "extended APDU rejected", rv: CKR_DEVICE_ERROR, kind: ErrInsNotSupported, sw: 0x6D00, wantExtAPDU: true},
		{name: "no PACE", rv: CKR_FUNCTION_NOT_SUPPORTED, kind: ErrUnsupportedCard, wantNoPACE: true},
		{name: "bad argument", rv: CKR_ARGUMENTS_BAD, kind: ErrNone},
		// A wrong PIN (fallback path) is not a wrong CAN.
		{name: "wrong PIN", rv: CKR_PIN_INCORRECT, kind: ErrWrongPin, sw: 0x63C2},
		// INS_NOT_SUPPORTED from the card itself (not CKR_DEVICE_ERROR)
		// is not the reader limitation.
		{name: "card INS not supported", rv: CKR_FUNCTION_FAILED, kind: ErrInsNotSupported, sw: 0x6D00},
	}
	for _, c := range cases {
		err := classifyReadError(c.rv, c.kind, c.sw)
		var ce *CardError
		if !errors.As(err, &ce) || ce.RV != c.rv || ce.Kind != c.kind || ce.SW != c.sw {
			t.Fatalf("%s: err = %#v", c.name, err)
		}
		var rv RV
		if !errors.As(err, &rv) || rv != c.rv {
			t.Errorf("%s: errors.As(RV) = %v", c.name, rv)
		}
		if got := errors.Is(err, ErrCANRejected); got != c.wantCAN {
			t.Errorf("%s: Is(ErrCANRejected) = %v", c.name, got)
		}
		if got := errors.Is(err, ErrExtendedAPDUNotSupported); got != c.wantExtAPDU {
			t.Errorf("%s: Is(ErrExtendedAPDUNotSupported) = %v", c.name, got)
		}
		if got := errors.Is(err, ErrPACENotSupported); got != c.wantNoPACE {
			t.Errorf("%s: Is(ErrPACENotSupported) = %v", c.name, got)
		}
		if err.Error() == "" {
			t.Errorf("%s: empty message", c.name)
		}
	}
}

func TestErrorToRV(t *testing.T) {
	if got := errorToRV(nil); got != CKR_OK {
		t.Errorf("nil -> %v", got)
	}
	if got := errorToRV(CKR_PIN_LOCKED); got != CKR_PIN_LOCKED {
		t.Errorf("RV -> %v", got)
	}
	wrapped := classifyReadError(CKR_DEVICE_ERROR, ErrNone, 0)
	if got := errorToRV(wrapped); got != CKR_DEVICE_ERROR {
		t.Errorf("wrapped RV -> %v", got)
	}
	if got := errorToRV(errors.New("boom")); got != CKR_FUNCTION_FAILED {
		t.Errorf("plain error -> %v", got)
	}
}

func TestCString(t *testing.T) {
	if got := cString([]byte("abc\x00def")); got != "abc" {
		t.Errorf("cString = %q", got)
	}
	if got := cString([]byte("abc")); got != "abc" {
		t.Errorf("cString without NUL = %q", got)
	}
	if got := cString([]byte{0, 'a'}); got != "" {
		t.Errorf("cString leading NUL = %q", got)
	}
}

func TestCheckDigestArgs(t *testing.T) {
	if err := checkDigestArgs(NIDSHA256, make([]byte, 32)); err != nil {
		t.Errorf("valid SHA-256: %v", err)
	}
	// The legacy README used 4 as the algid; it is not an OpenSSL NID.
	if err := checkDigestArgs(4, make([]byte, 32)); !errors.Is(err, ErrUnsupportedDigestAlgorithm) {
		t.Errorf("algid 4: %v", err)
	}
	if err := checkDigestArgs(NIDSHA256, make([]byte, 20)); !errors.Is(err, ErrInvalidDigestLength) {
		t.Errorf("short digest: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests that call into libopencie-pkcs11 (pure paths only: no reader or card
// is ever opened).
// ---------------------------------------------------------------------------

func TestClassifySW(t *testing.T) {
	cases := []struct {
		sw   uint16
		want ErrorKind
	}{
		{0x63C0, ErrWrongPin},
		{0x63C2, ErrWrongPin},
		{0x6300, ErrWrongPin},
		{0x6700, ErrWrongPin},
		{0x6983, ErrPinBlocked},
		{0x6984, ErrPinNotSet},
		{0x6982, ErrSecurityNotSatisfied},
		{0x6A82, ErrFileNotFound},
		{0x6A80, ErrWrongParams},
		{0x6A86, ErrWrongParams},
		{0x6A88, ErrWrongParams},
		{0x6B00, ErrWrongParams},
		{0x6D00, ErrInsNotSupported},
		{0x6E00, ErrInsNotSupported},
		{0x6F00, ErrUnknown},
	}
	for _, c := range cases {
		if got := ClassifySW(c.sw); got != c.want {
			t.Errorf("ClassifySW(%#04x) = %v, want %v", c.sw, got, c.want)
		}
	}
}

func TestLastErrorAfterArgumentError(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// A CAN that is not six digits is rejected before any reader access.
	_, err := ReadDGSCan("12345")
	var rv RV
	if !errors.As(err, &rv) || rv != CKR_ARGUMENTS_BAD {
		t.Fatalf("ReadDGSCan(short) = %v, want CKR_ARGUMENTS_BAD", err)
	}
	kind, sw := LastError()
	if kind == ErrWrongCan || sw != 0 {
		t.Errorf("LastError = (%v, %#04x) after an argument error", kind, sw)
	}
}

func TestReadDGSCanRejectsBadCAN(t *testing.T) {
	for _, can := range []string{"", "1", "12345", "1234567", "12345a", "abcdef", "12 456", "-12345"} {
		dg, err := ReadDGSCan(can)
		if dg != nil {
			t.Errorf("ReadDGSCan(%q): unexpected data", can)
		}
		var ce *CardError
		if !errors.As(err, &ce) || ce.RV != CKR_ARGUMENTS_BAD {
			t.Errorf("ReadDGSCan(%q) = %v, want CKR_ARGUMENTS_BAD", can, err)
			continue
		}
		if errors.Is(err, ErrCANRejected) || errors.Is(err, ErrExtendedAPDUNotSupported) {
			t.Errorf("ReadDGSCan(%q): argument error classified as a card failure", can)
		}
	}
}

func TestReadDGSRejectsBadPIN(t *testing.T) {
	cases := []struct {
		pin  string
		want RV
	}{
		{"", CKR_PIN_LEN_RANGE},
		{"1234567", CKR_PIN_LEN_RANGE},
		{"123456789", CKR_PIN_LEN_RANGE},
		{"1234567a", CKR_PIN_INVALID},
	}
	for _, c := range cases {
		dg, err := ReadDGS(c.pin)
		var rv RV
		if dg != nil || !errors.As(err, &rv) || rv != c.want {
			t.Errorf("ReadDGS(%q) = (%v, %v), want %v", c.pin, dg, err, c.want)
		}
	}
}

func TestEnableRejectsBadPIN(t *testing.T) {
	var attempts int
	err := Enable("1234567890123456", "123", &attempts, func(int, string) error {
		t.Error("progress callback must not run for a rejected PIN")
		return nil
	}, nil)
	var rv RV
	if !errors.As(err, &rv) || rv != CKR_PIN_LEN_RANGE {
		t.Errorf("Enable(short PIN) = %v, want CKR_PIN_LEN_RANGE", err)
	}
	err = Enable("1234567890123456", "1234567x", nil, nil, nil)
	if !errors.As(err, &rv) || rv != CKR_PIN_INVALID {
		t.Errorf("Enable(non-digit PIN) = %v, want CKR_PIN_INVALID", err)
	}
}

func TestMakeDigestInfo(t *testing.T) {
	// DER DigestInfo prefixes from RFC 8017 section 9.2, note 1.
	sum1 := sha1.Sum([]byte("opencie"))
	sum256 := sha256.Sum256([]byte("opencie"))
	sum384 := sha512.Sum384([]byte("opencie"))
	sum512 := sha512.Sum512([]byte("opencie"))
	cases := []struct {
		name   string
		algid  int
		digest []byte
		prefix string
	}{
		{"sha1", NIDSHA1, sum1[:], "3021300906052b0e03021a05000414"},
		{"sha256", NIDSHA256, sum256[:], "3031300d060960864801650304020105000420"},
		{"sha384", NIDSHA384, sum384[:], "3041300d060960864801650304020205000430"},
		{"sha512", NIDSHA512, sum512[:], "3051300d060960864801650304020305000440"},
	}
	for _, c := range cases {
		got, err := MakeDigestInfo(c.algid, c.digest)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		prefix := mustHex(t, c.prefix)
		want := append(append([]byte{}, prefix...), c.digest...)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: DigestInfo = %x, want %x", c.name, got, want)
		}
	}

	if _, err := MakeDigestInfo(NIDSHA256, nil); err == nil {
		t.Error("empty digest accepted")
	}
	if _, err := MakeDigestInfo(4, sum256[:]); !errors.Is(err, ErrUnsupportedDigestAlgorithm) {
		t.Errorf("algid 4: %v", err)
	}
	if _, err := MakeDigestInfo(NIDSHA256, sum1[:]); !errors.Is(err, ErrInvalidDigestLength) {
		t.Errorf("SHA-256 with a 20-byte digest: %v", err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range s[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c-'a') + 10
			default:
				t.Fatalf("bad hex %q", s)
			}
		}
		b[i] = v
	}
	return b
}

// cie_timestamp reports progress before it opens the input file, so a missing
// file exercises the Go callback trampolines without a card, a reader or the
// network.
func TestTimestampCallbacks(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.bin")
	out := filepath.Join(t.TempDir(), "out.tst")

	type call struct {
		progress int
		message  string
	}
	var calls []call
	err := Timestamp(missing, "http://127.0.0.1:1/tsa", "", "", out, func(p int, m string) error {
		calls = append(calls, call{p, m})
		return nil
	})
	var rv RV
	if !errors.As(err, &rv) || rv != CKR_DEVICE_ERROR {
		t.Fatalf("Timestamp(missing file) = %v, want CKR_DEVICE_ERROR", err)
	}
	if len(calls) != 1 || calls[0] != (call{10, "Reading file..."}) {
		t.Errorf("progress calls = %+v, want [{10 Reading file...}]", calls)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("token file written for a failed request")
	}

	// A nil callback must not crash the library (the C side calls it
	// unconditionally).
	if err := Timestamp(missing, "http://127.0.0.1:1/tsa", "", "", out, nil); !errors.As(err, &rv) || rv != CKR_DEVICE_ERROR {
		t.Errorf("Timestamp(nil callback) = %v", err)
	}

	// A callback error is handed to the library but does not change the
	// outcome of 1.3.0, which ignores the callback's return value.
	err = Timestamp(missing, "http://127.0.0.1:1/tsa", "", "", out, func(int, string) error {
		return errors.New("stop")
	})
	if !errors.As(err, &rv) || rv != CKR_DEVICE_ERROR {
		t.Errorf("Timestamp(erroring callback) = %v", err)
	}
}

func TestTimestampCallbackPanic(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.bin")
	out := filepath.Join(t.TempDir(), "out.tst")

	defer func() {
		if r := recover(); r != "callback panic" {
			t.Errorf("recovered %v, want the callback's panic value", r)
		}
		// The package state must be usable again after the panic.
		err := Timestamp(missing, "http://127.0.0.1:1/tsa", "", "", out, nil)
		var rv RV
		if !errors.As(err, &rv) || rv != CKR_DEVICE_ERROR {
			t.Errorf("Timestamp after panic = %v", err)
		}
	}()
	_ = Timestamp(missing, "http://127.0.0.1:1/tsa", "", "", out, func(int, string) error {
		panic("callback panic")
	})
	t.Error("Timestamp returned instead of re-raising the callback panic")
}
