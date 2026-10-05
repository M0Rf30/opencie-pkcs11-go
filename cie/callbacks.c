// SPDX-License-Identifier: MPL-2.0

// C trampolines handed to libopencie-pkcs11 as PROGRESS_CALLBACK,
// COMPLETED_CALLBACK and SIGN_COMPLETED_CALLBACK. The library calls them
// unconditionally and gives them no user-data pointer, so each one forwards
// to the matching //export function in cie.go. They live in their own file
// because a cgo file that uses //export may not define functions in its
// preamble.

#include <opencie/cie_ext.h>

#include "_cgo_export.h"

CK_RV opencie_go_progress(int progress, const char* message) {
	return goCieProgress(progress, (char*)message);
}

CK_RV opencie_go_completed(const char* pan, const char* name,
                           const char* serial) {
	return goCieCompleted((char*)pan, (char*)name, (char*)serial);
}

CK_RV opencie_go_sign_completed(int ret) {
	return goCieSignCompleted(ret);
}
