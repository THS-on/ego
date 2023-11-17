// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package attestation

// #include "claim.h"
// #include "sgx_evidence.h"
import "C"
import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/edgelesssys/ego/attestation/tcbstatus"
)

func ParseClaims(claims uintptr, claimsLength uintptr) (Report, error) {
	// https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices
	return parseClaims((*[1 << 28]C.oe_claim_t)(unsafe.Pointer(claims))[:claimsLength:claimsLength])
}

func parseClaims(claims []C.oe_claim_t) (Report, error) {
	report := Report{TCBStatus: tcbstatus.Unknown}
	hasAttributes := false
	var reportSGXRequired SGXRequired
	var requiredClaimCountSGX = 0

	for _, claim := range claims {
		switch C.GoString(claim.name) {
		case C.OE_CLAIM_SECURITY_VERSION:
			report.SecurityVersion = claimUint(claim)
		case C.OE_CLAIM_ATTRIBUTES:
			hasAttributes = true
			attr := claimUint(claim)
			if (attr & C.OE_EVIDENCE_ATTRIBUTES_SGX_REMOTE) == 0 {
				return Report{}, errors.New("not a remote report")
			}
			report.Debug = (attr & C.OE_EVIDENCE_ATTRIBUTES_SGX_DEBUG) != 0
		case C.OE_CLAIM_UNIQUE_ID:
			report.UniqueID = claimBytes(claim)
		case C.OE_CLAIM_SIGNER_ID:
			report.SignerID = claimBytes(claim)
		case C.OE_CLAIM_PRODUCT_ID:
			report.ProductID = claimBytes(claim)
		case C.OE_CLAIM_TCB_STATUS:
			report.TCBStatus = tcbstatus.Status(claimUint(claim))
		case C.OE_CLAIM_SGX_REPORT_DATA:
			report.Data = claimBytes(claim)
		case C.OE_CLAIM_UEID:
			// The UEID is prefixed with a type which is currently always OE_UEID_TYPE_RAND for SGX
			claimUEID := claimBytes(claim)
			if len(claimUEID) > 0 && claimUEID[0] != C.OE_UEID_TYPE_RAND {
				return Report{}, errors.New("Expected UEID of type OE_UEID_TYPE_RAND")
			}
			report.UEID = claimUEID
			// SGX Required claims
		case C.OE_CLAIM_SGX_PF_GP_EXINFO_ENABLED:
			reportSGXRequired.PfGpExinfoEnabled = claimBool(claim)
			requiredClaimCountSGX++
		case C.OE_CLAIM_SGX_ISV_EXTENDED_PRODUCT_ID:
			reportSGXRequired.ISVExtendedProductID = claimBytes(claim)
			requiredClaimCountSGX++
		case C.OE_CLAIM_SGX_IS_MODE64BIT:
			reportSGXRequired.IsMode64Bit = claimBool(claim)
			requiredClaimCountSGX++
		case C.OE_CLAIM_SGX_HAS_PROVISION_KEY:
			reportSGXRequired.HasProvisionKey = claimBool(claim)
		case C.OE_CLAIM_SGX_HAS_EINITTOKEN_KEY:
			reportSGXRequired.HasEINITTokenKey = claimBool(claim)
			requiredClaimCountSGX++
		case C.OE_CLAIM_SGX_USES_KSS:
			reportSGXRequired.UsesKSS = claimBool(claim)
			requiredClaimCountSGX++
		case C.OE_CLAIM_SGX_CONFIG_ID:
			reportSGXRequired.ConfigID = claimBytes(claim)
			requiredClaimCountSGX++
		case C.OE_CLAIM_SGX_CONFIG_SVN:
			reportSGXRequired.ConfigSVN = claimBytes(claim)
			requiredClaimCountSGX++
		case C.OE_CLAIM_SGX_ISV_FAMILY_ID:
			reportSGXRequired.ISVFamilyID = claimBytes(claim)
			requiredClaimCountSGX++
		case C.OE_CLAIM_SGX_CPU_SVN:
			reportSGXRequired.CPUSVN = claimBytes(claim)
			requiredClaimCountSGX++
		}

	}
	if requiredClaimCountSGX > 0 && requiredClaimCountSGX != C.OE_SGX_REQUIRED_CLAIMS_COUNT {
		return Report{}, fmt.Errorf("required SGX claims are missing. Only got: %d, expected: %d", requiredClaimCountSGX, C.OE_SGX_REQUIRED_CLAIMS_COUNT)
	}

	if !hasAttributes {
		return Report{}, errors.New("missing attributes in report claims")
	}

	if requiredClaimCountSGX > 0 {
		report.SGXRequired = &reportSGXRequired
	}

	return report, nil
}

func claimUint(claim C.oe_claim_t) uint {
	if claim.value_size < 4 {
		return 0
	}
	return uint(*(*C.uint32_t)(unsafe.Pointer(claim.value)))
}

func claimBool(claim C.oe_claim_t) bool {
	return bool(*(*C._Bool)(unsafe.Pointer(claim.value)))
}

func claimBytes(claim C.oe_claim_t) []byte {
	return C.GoBytes(unsafe.Pointer(claim.value), C.int(claim.value_size))
}
