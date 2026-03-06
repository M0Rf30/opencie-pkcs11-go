// Package sign provides cgo bindings for the sign SDK
// embedded in libopencie-pkcs11.
package sign

/*
#cgo LDFLAGS: -lopencie-pkcs11 -lstdc++
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Forward declarations to avoid C++ header inclusion
typedef void* CIE_SIGN_CTX;
typedef unsigned char BYTE;
typedef int BOOL;

#define MAX_LEN 256
#ifndef MAX_PATH
#define MAX_PATH 260
#endif

// Struct definitions (simplified to avoid C++ dependencies)
typedef struct {
  int nType;
  char szExpiration[60];
  char szThisUpdate[60];
  int nRevocationStatus;
  char szRevocationDate[60];
} REVOCATION_INFO;

typedef struct {
  char szCN[MAX_LEN * 2];
  char szDN[MAX_LEN * 2];
  char szGIVENNAME[MAX_LEN * 2];
  char szSURNAME[MAX_LEN * 2];
  char szSN[MAX_LEN * 2];
  char szCADN[MAX_LEN * 2];
  char** pszExtensions;
  int nExtensionsCount;
  char szExpiration[MAX_LEN];
  char szValidFrom[MAX_LEN];
  long bitmask;
  char szDigestAlgorithm[MAX_LEN];
  char szSigningTime[MAX_LEN];
  char szCertificateV2[MAX_LEN];
  BOOL b2011Error;
  BYTE* pCertificate;
  int nCertLen;
  void* pTimeStamp;
  REVOCATION_INFO* pRevocationInfo;
  void* pCounterSignatures;
  int nCounterSignatureCount;
} SIGNER_INFO;

typedef struct {
  SIGNER_INFO signerInfo;
  char szTimestamp[MAX_LEN];
  char szTimeStampImprintAlgorithm[MAX_LEN];
  char szTimeStampMessageImprint[MAX_LEN];
  char szTimeStampSerial[MAX_LEN];
} TS_INFO;

typedef struct {
  SIGNER_INFO* pSignerInfo;
  int nCount;
} SIGNER_INFOS;

typedef struct {
  SIGNER_INFOS* pSignerInfos;
  TS_INFO* pTSInfo;
} VERIFY_INFO;

typedef struct {
  int nResultType;
  BOOL bVerifyCRL;
  VERIFY_INFO verifyInfo;
  long nErrorCode;
  char szInputFile[MAX_PATH];
  char szPlainTextFile[MAX_PATH];
} VERIFY_RESULT;

typedef struct {
  char szLabel[MAX_LEN * 2];
  char szCN[MAX_LEN * 2];
  char szSN[MAX_LEN * 2];
  char szCACN[MAX_LEN * 2];
  char szExpiration[MAX_LEN];
  char szValidFrom[MAX_LEN];
  BYTE* pCertificate;
  int nCertLen;
} CERTIFICATE;

typedef struct {
  CERTIFICATE* pCertificate;
  int nCount;
} CERTIFICATES;

// Function declarations
extern long cie_sign_set(int option, void* value);
extern long cie_sign_set_int(int option, int value);
extern long cie_sign_set_string(int option, char* value);
extern void cie_sign_cleanup();
extern CIE_SIGN_CTX cie_sign_sign_init(void);
extern long cie_sign_sign_set_int(CIE_SIGN_CTX ctx, int option, int value);
extern long cie_sign_sign_set_string(CIE_SIGN_CTX ctx, int option, char* value);
extern long cie_sign_sign_set(CIE_SIGN_CTX ctx, int option, void* value);
extern long cie_sign_sign_sign(CIE_SIGN_CTX ctx);
extern long cie_sign_sign_cleanup(CIE_SIGN_CTX ctx);
extern long cie_sign_sign_getcertificates(CIE_SIGN_CTX ctx, CERTIFICATES* certs);
extern void cie_sign_sign_freecertificates(CERTIFICATES* certs);
extern CIE_SIGN_CTX cie_sign_verify_init(void);
extern long cie_sign_verify_set(CIE_SIGN_CTX ctx, int option, void* value);
extern long cie_sign_verify_set_int(CIE_SIGN_CTX ctx, int option, int value);
extern long cie_sign_verify_set_string(CIE_SIGN_CTX ctx, int option, char* value);
extern long cie_sign_verify_verify(CIE_SIGN_CTX ctx, VERIFY_RESULT* pVerifyResult);
extern long cie_sign_verify_cleanup_result(VERIFY_RESULT* pVerifyResult);
extern long cie_sign_verify_cleanup(CIE_SIGN_CTX ctx);
extern long cie_sign_get_file_from_p7m(CIE_SIGN_CTX ctx);

// Constants
#define CIE_SIGN_OPT_PKCS11 1
#define CIE_SIGN_OPT_SLOT 2
#define CIE_SIGN_OPT_PIN 3
#define CIE_SIGN_OPT_ALIAS 4
#define CIE_SIGN_OPT_CADES 5
#define CIE_SIGN_OPT_XADES 5
#define CIE_SIGN_OPT_DETACHED 6
#define CIE_SIGN_OPT_INPUTFILE 7
#define CIE_SIGN_OPT_OUTPUTFILE 8
#define CIE_SIGN_OPT_INPUTFILE_TYPE 9
#define CIE_SIGN_OPT_TSA_URL 10
#define CIE_SIGN_OPT_TSA_USERNAME 11
#define CIE_SIGN_OPT_TSA_PASSWORD 12
#define CIE_SIGN_OPT_VERIFY_REVOCATION 13
#define CIE_SIGN_OPT_LOG_LEVEL 14
#define CIE_SIGN_OPT_LOG_FILE 15
#define CIE_SIGN_OPT_INPUTFILE_PLAINTEXT 16
#define CIE_SIGN_OPT_CACERT_DIR 17
#define CIE_SIGN_OPT_PDF_SUBFILTER 18
#define CIE_SIGN_OPT_CONFIG_FILE 19
#define CIE_SIGN_OPT_PROXY 20
#define CIE_SIGN_OPT_PROXY_PORT 21
#define CIE_SIGN_OPT_PROXY_USRPASS 22
#define CIE_SIGN_OPT_OID_MAP_FILE 23
#define CIE_SIGN_OPT_TCP_TIMEOUT 24
#define CIE_SIGN_OPT_PDF_REASON 25
#define CIE_SIGN_OPT_PDF_NAME 26
#define CIE_SIGN_OPT_PDF_LOCATION 27
#define CIE_SIGN_OPT_PDF_PAGE 28
#define CIE_SIGN_OPT_PDF_LEFT 29
#define CIE_SIGN_OPT_PDF_BOTTOM 30
#define CIE_SIGN_OPT_PDF_WIDTH 31
#define CIE_SIGN_OPT_PDF_HEIGHT 32
#define CIE_SIGN_OPT_PDF_IMAGEPATH 33
#define CIE_SIGN_OPT_PDF_GRAPHOMETRIC_DATA 34
#define CIE_SIGN_OPT_PDF_GRAPHOMETRIC_DATA_VER 35
#define CIE_SIGN_OPT_ATR_LIST_FILE 36
#define CIE_SIGN_OPT_HASH_ALGO 37
#define CIE_SIGN_OPT_LICENSEE 38
#define CIE_SIGN_OPT_PRODUCTKEY 39
#define CIE_SIGN_OPT_RS_OTP_PIN 40
#define CIE_SIGN_OPT_RS_HSMTYPE 41
#define CIE_SIGN_OPT_RS_TYPE_OTP_AUTH 42
#define CIE_SIGN_OPT_RS_USERNAME 43
#define CIE_SIGN_OPT_RS_PASSWORD 44
#define CIE_SIGN_OPT_RS_CERTID 45
#define CIE_SIGN_OPT_RS_SERVICE_URL 46
#define CIE_SIGN_OPT_RS_USER_CODE 47
#define CIE_SIGN_OPT_RS_SERVICE_TYPE 48
#define CIE_SIGN_OPT_PDF_DESCRIPTION 50
#define CIE_SIGN_OPT_PDF_NAME_LABEL 51
#define CIE_SIGN_OPT_PDF_REASON_LABEL 52
#define CIE_SIGN_OPT_PDF_LOCATION_LABEL 53
#define CIE_SIGN_OPT_TSL_URL 60
#define CIE_SIGN_OPT_VERIFY_USER_CERTIFICATE 61
#define CIE_SIGN_OPT_P12_FILEPATH 70
#define CIE_SIGN_OPT_P12_PASSWORD 71
#define CIE_SIGN_OPT_IAS_INSTANCE 80

#define CIE_SIGN_PDF_SUBFILTER_PKCS_DETACHED "adbe.pkcs7.detached"
#define CIE_SIGN_PDF_SUBFILTER_ETSI_CADES "ETSI.CAdES.detached"

#define CIE_SIGN_ERROR_BASE 0x84000000UL
#define CIE_SIGN_ERROR_UNEXPECTED (CIE_SIGN_ERROR_BASE + 1)
#define CIE_SIGN_ERROR_FILE_NOT_FOUND (CIE_SIGN_ERROR_BASE + 2)
#define CIE_SIGN_ERROR_DETACHED_PKCS7 (CIE_SIGN_ERROR_BASE + 3)
#define CIE_SIGN_ERROR_CERT_REVOKED (CIE_SIGN_ERROR_BASE + 4)
#define CIE_SIGN_ERROR_INVALID_FILE (CIE_SIGN_ERROR_BASE + 5)
#define CIE_SIGN_ERROR_INVALID_P11 (CIE_SIGN_ERROR_BASE + 6)
#define CIE_SIGN_ERROR_INVALID_ALIAS (CIE_SIGN_ERROR_BASE + 7)
#define CIE_SIGN_ERROR_INVALID_SIGOPT (CIE_SIGN_ERROR_BASE + 8)
#define CIE_SIGN_ERROR_ARRS_BASE (CIE_SIGN_ERROR_BASE + 0x00100000)
#define CIE_SIGN_ERROR_CERT_INVALID (CIE_SIGN_ERROR_BASE + 9)
#define CIE_SIGN_ERROR_CERT_EXPIRED (CIE_SIGN_ERROR_BASE + 10)
#define CIE_SIGN_ERROR_CACERT_NOTFOUND (CIE_SIGN_ERROR_BASE + 11)
#define CIE_SIGN_ERROR_CERT_NOTFOUND (CIE_SIGN_ERROR_BASE + 12)
#define CIE_SIGN_ERROR_CERT_NOT_FOR_SIGNATURE (CIE_SIGN_ERROR_BASE + 13)
#define CIE_SIGN_ERROR_TSL_LOAD (CIE_SIGN_ERROR_BASE + 20)
#define CIE_SIGN_ERROR_TSL_PARSE (CIE_SIGN_ERROR_BASE + 21)
#define CIE_SIGN_ERROR_TSL_INVALID (CIE_SIGN_ERROR_BASE + 22)
#define CIE_SIGN_ERROR_TSL_CACERTDIR_NOT_SET (CIE_SIGN_ERROR_BASE + 23)
#define CIE_SIGN_ERROR_TSA (CIE_SIGN_ERROR_BASE + 30)
#define CIE_SIGN_ERROR_WRONG_PIN (CIE_SIGN_ERROR_BASE + 40)
#define CIE_SIGN_ERROR_PIN_LOCKED (CIE_SIGN_ERROR_BASE + 41)

#define CIE_SIGN_FILETYPE_PLAINTEXT 0
#define CIE_SIGN_FILETYPE_P7M 1
#define CIE_SIGN_FILETYPE_PDF 2
#define CIE_SIGN_FILETYPE_M7M 3
#define CIE_SIGN_FILETYPE_TSR 4
#define CIE_SIGN_FILETYPE_TST 5
#define CIE_SIGN_FILETYPE_TSD 6
#define CIE_SIGN_FILETYPE_XML 7
#define CIE_SIGN_FILETYPE_AUTO 8

#define CIE_SIGN_ALGO_SHA1 1
#define CIE_SIGN_ALGO_SHA256 2
#define CIE_SIGN_ALGO_SHA512 3
#define CIE_SIGN_ALGO_MD5 4

#define REVOCATION_STATUS_GOOD 0
#define REVOCATION_STATUS_REVOKED 1
#define REVOCATION_STATUS_SUSPENDED 2
#define REVOCATION_STATUS_UNKNOWN 3
#define REVOCATION_STATUS_NOTLOADED 4
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Ctx is an opaque context handle for sign operations (CIE_SIGN_CTX).
type Ctx C.CIE_SIGN_CTX

// Option constants for sign_set* functions
const (
	OptPKCS11                 = C.CIE_SIGN_OPT_PKCS11
	OptSlot                   = C.CIE_SIGN_OPT_SLOT
	OptPin                    = C.CIE_SIGN_OPT_PIN
	OptAlias                  = C.CIE_SIGN_OPT_ALIAS
	OptCAdES                  = C.CIE_SIGN_OPT_CADES
	OptXAdES                  = C.CIE_SIGN_OPT_XADES
	OptDetached               = C.CIE_SIGN_OPT_DETACHED
	OptInputFile              = C.CIE_SIGN_OPT_INPUTFILE
	OptOutputFile             = C.CIE_SIGN_OPT_OUTPUTFILE
	OptInputFileType          = C.CIE_SIGN_OPT_INPUTFILE_TYPE
	OptTSAURL                 = C.CIE_SIGN_OPT_TSA_URL
	OptTSAUsername            = C.CIE_SIGN_OPT_TSA_USERNAME
	OptTSAPassword            = C.CIE_SIGN_OPT_TSA_PASSWORD
	OptVerifyRevocation       = C.CIE_SIGN_OPT_VERIFY_REVOCATION
	OptLogLevel               = C.CIE_SIGN_OPT_LOG_LEVEL
	OptLogFile                = C.CIE_SIGN_OPT_LOG_FILE
	OptInputFilePlaintext     = C.CIE_SIGN_OPT_INPUTFILE_PLAINTEXT
	OptCACertDir              = C.CIE_SIGN_OPT_CACERT_DIR
	OptPDFSubfilter           = C.CIE_SIGN_OPT_PDF_SUBFILTER
	OptConfigFile             = C.CIE_SIGN_OPT_CONFIG_FILE
	OptProxy                  = C.CIE_SIGN_OPT_PROXY
	OptProxyPort              = C.CIE_SIGN_OPT_PROXY_PORT
	OptProxyUsrPass           = C.CIE_SIGN_OPT_PROXY_USRPASS
	OptOIDMapFile             = C.CIE_SIGN_OPT_OID_MAP_FILE
	OptTCPTimeout             = C.CIE_SIGN_OPT_TCP_TIMEOUT
	OptPDFReason              = C.CIE_SIGN_OPT_PDF_REASON
	OptPDFName                = C.CIE_SIGN_OPT_PDF_NAME
	OptPDFLocation            = C.CIE_SIGN_OPT_PDF_LOCATION
	OptPDFPage                = C.CIE_SIGN_OPT_PDF_PAGE
	OptPDFLeft                = C.CIE_SIGN_OPT_PDF_LEFT
	OptPDFBottom              = C.CIE_SIGN_OPT_PDF_BOTTOM
	OptPDFWidth               = C.CIE_SIGN_OPT_PDF_WIDTH
	OptPDFHeight              = C.CIE_SIGN_OPT_PDF_HEIGHT
	OptPDFImagePath           = C.CIE_SIGN_OPT_PDF_IMAGEPATH
	OptPDFGraphometricData    = C.CIE_SIGN_OPT_PDF_GRAPHOMETRIC_DATA
	OptPDFGraphometricDataVer = C.CIE_SIGN_OPT_PDF_GRAPHOMETRIC_DATA_VER
	OptATRListFile            = C.CIE_SIGN_OPT_ATR_LIST_FILE
	OptHashAlgo               = C.CIE_SIGN_OPT_HASH_ALGO
	OptLicensee               = C.CIE_SIGN_OPT_LICENSEE
	OptProductKey             = C.CIE_SIGN_OPT_PRODUCTKEY
	OptRSOTPPin               = C.CIE_SIGN_OPT_RS_OTP_PIN
	OptRSHSMType              = C.CIE_SIGN_OPT_RS_HSMTYPE
	OptRSTypeOTPAuth          = C.CIE_SIGN_OPT_RS_TYPE_OTP_AUTH
	OptRSUsername             = C.CIE_SIGN_OPT_RS_USERNAME
	OptRSPassword             = C.CIE_SIGN_OPT_RS_PASSWORD
	OptRSCertID               = C.CIE_SIGN_OPT_RS_CERTID
	OptRSServiceURL           = C.CIE_SIGN_OPT_RS_SERVICE_URL
	OptRSUserCode             = C.CIE_SIGN_OPT_RS_USER_CODE
	OptRSServiceType          = C.CIE_SIGN_OPT_RS_SERVICE_TYPE
	OptPDFDescription         = C.CIE_SIGN_OPT_PDF_DESCRIPTION
	OptPDFNameLabel           = C.CIE_SIGN_OPT_PDF_NAME_LABEL
	OptPDFReasonLabel         = C.CIE_SIGN_OPT_PDF_REASON_LABEL
	OptPDFLocationLabel       = C.CIE_SIGN_OPT_PDF_LOCATION_LABEL
	OptTSLURL                 = C.CIE_SIGN_OPT_TSL_URL
	OptVerifyUserCertificate  = C.CIE_SIGN_OPT_VERIFY_USER_CERTIFICATE
	OptP12FilePath            = C.CIE_SIGN_OPT_P12_FILEPATH
	OptP12Password            = C.CIE_SIGN_OPT_P12_PASSWORD
	OptIASInstance            = C.CIE_SIGN_OPT_IAS_INSTANCE
)

// File type constants
const (
	FileTypePlaintext = C.CIE_SIGN_FILETYPE_PLAINTEXT
	FileTypeP7M       = C.CIE_SIGN_FILETYPE_P7M
	FileTypePDF       = C.CIE_SIGN_FILETYPE_PDF
	FileTypeM7M       = C.CIE_SIGN_FILETYPE_M7M
	FileTypeTSR       = C.CIE_SIGN_FILETYPE_TSR
	FileTypeTST       = C.CIE_SIGN_FILETYPE_TST
	FileTypeTSD       = C.CIE_SIGN_FILETYPE_TSD
	FileTypeXML       = C.CIE_SIGN_FILETYPE_XML
	FileTypeAuto      = C.CIE_SIGN_FILETYPE_AUTO
)

// Hash algorithm constants
const (
	AlgoSHA1   = C.CIE_SIGN_ALGO_SHA1
	AlgoSHA256 = C.CIE_SIGN_ALGO_SHA256
	AlgoSHA512 = C.CIE_SIGN_ALGO_SHA512
	AlgoMD5    = C.CIE_SIGN_ALGO_MD5
)

// PDF subfilter constants
const (
	PDFSubfilterPKCSDetached = C.CIE_SIGN_PDF_SUBFILTER_PKCS_DETACHED
	PDFSubfilterETSICAdES    = C.CIE_SIGN_PDF_SUBFILTER_ETSI_CADES
)

// Error codes
const (
	ErrorBase                = C.CIE_SIGN_ERROR_BASE
	ErrorUnexpected          = C.CIE_SIGN_ERROR_UNEXPECTED
	ErrorFileNotFound        = C.CIE_SIGN_ERROR_FILE_NOT_FOUND
	ErrorDetachedPKCS7       = C.CIE_SIGN_ERROR_DETACHED_PKCS7
	ErrorCertRevoked         = C.CIE_SIGN_ERROR_CERT_REVOKED
	ErrorInvalidFile         = C.CIE_SIGN_ERROR_INVALID_FILE
	ErrorInvalidP11          = C.CIE_SIGN_ERROR_INVALID_P11
	ErrorInvalidAlias        = C.CIE_SIGN_ERROR_INVALID_ALIAS
	ErrorInvalidSigOpt       = C.CIE_SIGN_ERROR_INVALID_SIGOPT
	ErrorARRSBase            = C.CIE_SIGN_ERROR_ARRS_BASE
	ErrorCertInvalid         = C.CIE_SIGN_ERROR_CERT_INVALID
	ErrorCertExpired         = C.CIE_SIGN_ERROR_CERT_EXPIRED
	ErrorCACertNotFound      = C.CIE_SIGN_ERROR_CACERT_NOTFOUND
	ErrorCertNotFound        = C.CIE_SIGN_ERROR_CERT_NOTFOUND
	ErrorCertNotForSignature = C.CIE_SIGN_ERROR_CERT_NOT_FOR_SIGNATURE
	ErrorTSLLoad             = C.CIE_SIGN_ERROR_TSL_LOAD
	ErrorTSLParse            = C.CIE_SIGN_ERROR_TSL_PARSE
	ErrorTSLInvalid          = C.CIE_SIGN_ERROR_TSL_INVALID
	ErrorTSLCACertDirNotSet  = C.CIE_SIGN_ERROR_TSL_CACERTDIR_NOT_SET
	ErrorTSA                 = C.CIE_SIGN_ERROR_TSA
	ErrorWrongPin            = C.CIE_SIGN_ERROR_WRONG_PIN
	ErrorPinLocked           = C.CIE_SIGN_ERROR_PIN_LOCKED
)

// Revocation status constants
const (
	RevocationStatusGood      = C.REVOCATION_STATUS_GOOD
	RevocationStatusRevoked   = C.REVOCATION_STATUS_REVOKED
	RevocationStatusSuspended = C.REVOCATION_STATUS_SUSPENDED
	RevocationStatusUnknown   = C.REVOCATION_STATUS_UNKNOWN
	RevocationStatusNotLoaded = C.REVOCATION_STATUS_NOTLOADED
)

// RevocationInfo represents revocation information for a certificate.
type RevocationInfo struct {
	Type             int // TYPE_OCSP, TYPE_CRL
	Expiration       string
	ThisUpdate       string
	RevocationStatus int
	RevocationDate   string
}

// SignerInfo contains information about a signer.
type SignerInfo struct {
	CN                    string
	DN                    string
	GivenName             string
	Surname               string
	SN                    string
	CADN                  string
	Extensions            []string
	Expiration            string
	ValidFrom             string
	Bitmask               int64
	DigestAlgorithm       string
	SigningTime           string
	CertificateV2         string
	Has2011Error          bool
	Certificate           []byte
	TimeStamp             unsafe.Pointer
	RevocationInfo        *RevocationInfo
	CounterSignatures     unsafe.Pointer
	CounterSignatureCount int
}

// TSInfo represents timestamp information.
type TSInfo struct {
	SignerInfo                SignerInfo
	Timestamp                 string
	TimestampImprintAlgorithm string
	TimestampMessageImprint   string
	TimestampSerial           string
}

// VerifyInfo contains verification information.
type VerifyInfo struct {
	SignerInfos []SignerInfo
	TSInfo      *TSInfo
}

// VerifyResult represents the result of a verification operation.
type VerifyResult struct {
	ResultType    int
	VerifyCRL     bool
	VerifyInfo    VerifyInfo
	ErrorCode     int64
	InputFile     string
	PlainTextFile string
}

// Certificate represents a certificate with its metadata.
type Certificate struct {
	Label       string
	CN          string
	SN          string
	CACN        string
	Expiration  string
	ValidFrom   string
	Certificate []byte
}

// Set sets a global option for the sign library.
func Set(option int, value unsafe.Pointer) error {
	rv := C.cie_sign_set(C.int(option), value)
	if rv != 0 {
		return fmt.Errorf("cie_sign_set failed: 0x%08X", uint64(rv))
	}
	return nil
}

// SetInt sets a global integer option for the sign library.
func SetInt(option, value int) error {
	rv := C.cie_sign_set_int(C.int(option), C.int(value))
	if rv != 0 {
		return fmt.Errorf("cie_sign_set_int failed: 0x%08X", uint64(rv))
	}
	return nil
}

// SetString sets a global string option for the sign library.
func SetString(option int, value string) error {
	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cValue))
	rv := C.cie_sign_set_string(C.int(option), cValue)
	if rv != 0 {
		return fmt.Errorf("cie_sign_set_string failed: 0x%08X", uint64(rv))
	}
	return nil
}

// Cleanup frees memory allocated by the sign library.
func Cleanup() {
	C.cie_sign_cleanup()
}

// SignInit initializes a signing operation and returns a context.
func SignInit() Ctx {
	return Ctx(C.cie_sign_sign_init())
}

// SignSetInt sets an integer option for a signing operation.
func SignSetInt(ctx Ctx, option, value int) error {
	rv := C.cie_sign_sign_set_int(C.CIE_SIGN_CTX(ctx), C.int(option), C.int(value))
	if rv != 0 {
		return fmt.Errorf("cie_sign_sign_set_int failed: 0x%08X", uint64(rv))
	}
	return nil
}

// SignSetString sets a string option for a signing operation.
func SignSetString(ctx Ctx, option int, value string) error {
	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cValue))
	rv := C.cie_sign_sign_set_string(C.CIE_SIGN_CTX(ctx), C.int(option), cValue)
	if rv != 0 {
		return fmt.Errorf("cie_sign_sign_set_string failed: 0x%08X", uint64(rv))
	}
	return nil
}

// SignSet sets a pointer option for a signing operation.
func SignSet(ctx Ctx, option int, value unsafe.Pointer) error {
	rv := C.cie_sign_sign_set(C.CIE_SIGN_CTX(ctx), C.int(option), value)
	if rv != 0 {
		return fmt.Errorf("cie_sign_sign_set failed: 0x%08X", uint64(rv))
	}
	return nil
}

// SignSign performs the signing operation according to the set options.
func SignSign(ctx Ctx) error {
	rv := C.cie_sign_sign_sign(C.CIE_SIGN_CTX(ctx))
	if rv != 0 {
		return fmt.Errorf("cie_sign_sign_sign failed: 0x%08X", uint64(rv))
	}
	return nil
}

// SignCleanup frees memory allocated for a signing operation.
func SignCleanup(ctx Ctx) error {
	rv := C.cie_sign_sign_cleanup(C.CIE_SIGN_CTX(ctx))
	if rv != 0 {
		return fmt.Errorf("cie_sign_sign_cleanup failed: 0x%08X", uint64(rv))
	}
	return nil
}

// SignGetCertificates retrieves the list of available certificates.
func SignGetCertificates(ctx Ctx) ([]Certificate, error) {
	var cCerts C.CERTIFICATES
	rv := C.cie_sign_sign_getcertificates(C.CIE_SIGN_CTX(ctx), &cCerts)
	if rv != 0 {
		return nil, fmt.Errorf("cie_sign_sign_getcertificates failed: 0x%08X", uint64(rv))
	}

	if cCerts.nCount == 0 || cCerts.pCertificate == nil {
		return []Certificate{}, nil
	}

	// Convert C array to Go slice
	count := int(cCerts.nCount)
	certs := make([]Certificate, count)

	// Access C array elements
	cCertArray := (*[1 << 30]C.CERTIFICATE)(unsafe.Pointer(cCerts.pCertificate))[:count:count]

	for i := 0; i < count; i++ {
		cCert := &cCertArray[i]
		certs[i] = Certificate{
			Label:      C.GoString(&cCert.szLabel[0]),
			CN:         C.GoString(&cCert.szCN[0]),
			SN:         C.GoString(&cCert.szSN[0]),
			CACN:       C.GoString(&cCert.szCACN[0]),
			Expiration: C.GoString(&cCert.szExpiration[0]),
			ValidFrom:  C.GoString(&cCert.szValidFrom[0]),
		}

		if cCert.pCertificate != nil && cCert.nCertLen > 0 {
			certs[i].Certificate = C.GoBytes(unsafe.Pointer(cCert.pCertificate), cCert.nCertLen)
		}
	}

	// Free the certificates
	C.cie_sign_sign_freecertificates(&cCerts)

	return certs, nil
}

// SignFreeCertificates is a no-op in Go (memory is managed by the C side).
// This is kept for API compatibility.
func SignFreeCertificates(certs *[]Certificate) {
	// No-op: memory already freed in SignGetCertificates
}

// VerifyInit initializes a verification operation and returns a context.
func VerifyInit() Ctx {
	return Ctx(C.cie_sign_verify_init())
}

// VerifySet sets a pointer option for a verification operation.
func VerifySet(ctx Ctx, option int, value unsafe.Pointer) error {
	rv := C.cie_sign_verify_set(C.CIE_SIGN_CTX(ctx), C.int(option), value)
	if rv != 0 {
		return fmt.Errorf("cie_sign_verify_set failed: 0x%08X", uint64(rv))
	}
	return nil
}

// VerifySetInt sets an integer option for a verification operation.
func VerifySetInt(ctx Ctx, option, value int) error {
	rv := C.cie_sign_verify_set_int(C.CIE_SIGN_CTX(ctx), C.int(option), C.int(value))
	if rv != 0 {
		return fmt.Errorf("cie_sign_verify_set_int failed: 0x%08X", uint64(rv))
	}
	return nil
}

// VerifySetString sets a string option for a verification operation.
func VerifySetString(ctx Ctx, option int, value string) error {
	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cValue))
	rv := C.cie_sign_verify_set_string(C.CIE_SIGN_CTX(ctx), C.int(option), cValue)
	if rv != 0 {
		return fmt.Errorf("cie_sign_verify_set_string failed: 0x%08X", uint64(rv))
	}
	return nil
}

// VerifyVerify performs the verification operation and returns the result.
func VerifyVerify(ctx Ctx) (*VerifyResult, error) {
	var cResult C.VERIFY_RESULT
	rv := C.cie_sign_verify_verify(C.CIE_SIGN_CTX(ctx), &cResult)
	if rv != 0 {
		return nil, fmt.Errorf("cie_sign_verify_verify failed: 0x%08X", uint64(rv))
	}

	result := &VerifyResult{
		ResultType:    int(cResult.nResultType),
		VerifyCRL:     cResult.bVerifyCRL != 0,
		ErrorCode:     int64(cResult.nErrorCode),
		InputFile:     C.GoString(&cResult.szInputFile[0]),
		PlainTextFile: C.GoString(&cResult.szPlainTextFile[0]),
	}

	// Marshal VerifyInfo (simplified - full implementation would need to handle nested structures)
	if cResult.verifyInfo.pSignerInfos != nil && cResult.verifyInfo.pSignerInfos.nCount > 0 {
		count := int(cResult.verifyInfo.pSignerInfos.nCount)
		result.VerifyInfo.SignerInfos = make([]SignerInfo, count)

		cSignerArray := (*[1 << 30]C.SIGNER_INFO)(unsafe.Pointer(cResult.verifyInfo.pSignerInfos.pSignerInfo))[:count:count]

		for i := 0; i < count; i++ {
			cSigner := &cSignerArray[i]
			result.VerifyInfo.SignerInfos[i] = SignerInfo{
				CN:              C.GoString(&cSigner.szCN[0]),
				DN:              C.GoString(&cSigner.szDN[0]),
				GivenName:       C.GoString(&cSigner.szGIVENNAME[0]),
				Surname:         C.GoString(&cSigner.szSURNAME[0]),
				SN:              C.GoString(&cSigner.szSN[0]),
				CADN:            C.GoString(&cSigner.szCADN[0]),
				Expiration:      C.GoString(&cSigner.szExpiration[0]),
				ValidFrom:       C.GoString(&cSigner.szValidFrom[0]),
				Bitmask:         int64(cSigner.bitmask),
				DigestAlgorithm: C.GoString(&cSigner.szDigestAlgorithm[0]),
				SigningTime:     C.GoString(&cSigner.szSigningTime[0]),
				CertificateV2:   C.GoString(&cSigner.szCertificateV2[0]),
				Has2011Error:    cSigner.b2011Error != 0,
			}

			if cSigner.pCertificate != nil && cSigner.nCertLen > 0 {
				result.VerifyInfo.SignerInfos[i].Certificate = C.GoBytes(unsafe.Pointer(cSigner.pCertificate), C.int(cSigner.nCertLen))
			}

			// Handle RevocationInfo if present
			if cSigner.pRevocationInfo != nil {
				cRevoc := (*C.REVOCATION_INFO)(unsafe.Pointer(cSigner.pRevocationInfo))
				result.VerifyInfo.SignerInfos[i].RevocationInfo = &RevocationInfo{
					Type:             int(cRevoc.nType),
					Expiration:       C.GoString(&cRevoc.szExpiration[0]),
					ThisUpdate:       C.GoString(&cRevoc.szThisUpdate[0]),
					RevocationStatus: int(cRevoc.nRevocationStatus),
					RevocationDate:   C.GoString(&cRevoc.szRevocationDate[0]),
				}
			}
		}
	}

	// Clean up the C result
	C.cie_sign_verify_cleanup_result(&cResult)

	return result, nil
}

// VerifyCleanupResult frees memory allocated for a verification result.
// Note: This is automatically called in VerifyVerify, so manual calling is usually not needed.
func VerifyCleanupResult(result *C.VERIFY_RESULT) error {
	rv := C.cie_sign_verify_cleanup_result(result)
	if rv != 0 {
		return fmt.Errorf("cie_sign_verify_cleanup_result failed: 0x%08X", uint64(rv))
	}
	return nil
}

// VerifyCleanup frees memory allocated for a verification operation.
func VerifyCleanup(ctx Ctx) error {
	rv := C.cie_sign_verify_cleanup(C.CIE_SIGN_CTX(ctx))
	if rv != 0 {
		return fmt.Errorf("cie_sign_verify_cleanup failed: 0x%08X", uint64(rv))
	}
	return nil
}

// GetFileFromP7M extracts the original document from a p7m file.
func GetFileFromP7M(ctx Ctx) error {
	rv := C.cie_sign_get_file_from_p7m(C.CIE_SIGN_CTX(ctx))
	if rv != 0 {
		return fmt.Errorf("cie_sign_get_file_from_p7m failed: 0x%08X", uint64(rv))
	}
	return nil
}
