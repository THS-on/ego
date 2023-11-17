// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package attestation

import (
	"errors"

	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/ego/internal/attestation"
)

// Report is a parsed enclave report.
type Report struct {
	Data            []byte           // The report data that has been included in the report.
	SecurityVersion uint             // Security version of the enclave. For SGX enclaves, this is the ISVSVN value.
	Debug           bool             // If true, the report is for a debug enclave.
	UniqueID        []byte           // The unique ID for the enclave. For SGX enclaves, this is the MRENCLAVE value.
	SignerID        []byte           // The signer ID for the enclave. For SGX enclaves, this is the MRSIGNER value.
	ProductID       []byte           // The Product ID for the enclave. For SGX enclaves, this is the ISVPRODID value.
	TCBStatus       tcbstatus.Status // The status of the enclave's TCB level.
	UEID            []byte           // The universal entity ID. For SGX enclaves, this is QE identity value with an additional first bit that indicates the OE UEID type.
	SGXRequired     *SGXRequired
}

type SGXRequired struct {
	PfGpExinfoEnabled    bool
	ISVExtendedProductID []byte
	IsMode64Bit          bool
	HasProvisionKey      bool
	HasEINITTokenKey     bool
	UsesKSS              bool
	ConfigID             []byte
	ConfigSVN            []byte
	ISVFamilyID          []byte
	CPUSVN               []byte
}

func FromInternal(internal attestation.Report) Report {
	var reportSGXRequired SGXRequired
	if internal.SGXRequired != nil {
		reportSGXRequired = SGXRequired{
			PfGpExinfoEnabled:    internal.SGXRequired.PfGpExinfoEnabled,
			ISVExtendedProductID: internal.SGXRequired.ISVExtendedProductID,
			IsMode64Bit:          internal.SGXRequired.IsMode64Bit,
			HasProvisionKey:      internal.SGXRequired.HasProvisionKey,
			HasEINITTokenKey:     internal.SGXRequired.HasEINITTokenKey,
			UsesKSS:              internal.SGXRequired.UsesKSS,
			ConfigID:             internal.SGXRequired.ConfigID,
			ConfigSVN:            internal.SGXRequired.ConfigSVN,
			ISVFamilyID:          internal.SGXRequired.ISVFamilyID,
			CPUSVN:               internal.SGXRequired.CPUSVN,
		}
	}

	return Report{
		Data:            internal.Data,
		SecurityVersion: internal.SecurityVersion,
		Debug:           internal.Debug,
		UniqueID:        internal.UniqueID,
		SignerID:        internal.SignerID,
		ProductID:       internal.ProductID,
		TCBStatus:       internal.TCBStatus,
		UEID:            internal.UEID,
		SGXRequired:     &reportSGXRequired,
	}
}

func (report Report) ToInternal() attestation.Report {
	var reportSGXRequired attestation.SGXRequired
	if report.SGXRequired != nil {
		reportSGXRequired = attestation.SGXRequired{
			PfGpExinfoEnabled:    report.SGXRequired.PfGpExinfoEnabled,
			ISVExtendedProductID: report.SGXRequired.ISVExtendedProductID,
			IsMode64Bit:          report.SGXRequired.IsMode64Bit,
			HasProvisionKey:      report.SGXRequired.HasProvisionKey,
			HasEINITTokenKey:     report.SGXRequired.HasEINITTokenKey,
			UsesKSS:              report.SGXRequired.UsesKSS,
			ConfigID:             report.SGXRequired.ConfigID,
			ConfigSVN:            report.SGXRequired.ConfigSVN,
			ISVFamilyID:          report.SGXRequired.ISVFamilyID,
			CPUSVN:               report.SGXRequired.CPUSVN,
		}
	}

	return attestation.Report{
		Data:            report.Data,
		SecurityVersion: report.SecurityVersion,
		Debug:           report.Debug,
		UniqueID:        report.UniqueID,
		SignerID:        report.SignerID,
		ProductID:       report.ProductID,
		TCBStatus:       report.TCBStatus,
		UEID:            report.UEID,
		SGXRequired:     &reportSGXRequired,
	}
}

var (
	// ErrEmptyReport is returned by VerifyRemoteReport if reportBytes is empty.
	ErrEmptyReport = errors.New("empty report")

	// ErrTCBLevelInvalid is returned if VerifyRemoteReport succeeded, but the TCB is not considered up-to-date. Check the report's TCBStatus.
	ErrTCBLevelInvalid = errors.New("OE_TCB_LEVEL_INVALID")
)

// VerifyAzureAttestationToken takes a Microsoft Azure Attestation token in JSON Web Token compact
// serialization format and verifies the token's public claims and signature. The attestation provider's
// keys are loaded from providerURL over TLS. The validation is based on the trust in this TLS channel.
// Note that the token's issuer (iss) has to be equal to the providerURL, and providerURL must use the HTTPS scheme.
//
// The caller must verify the returned report's content.
//
// This function relies on the root CA certificates of the host to verify the TLS connection. Thus, it is currently
// usable by non-enclaved clients only. A future version of EGo will allow to add root certificates to an enclave.
func VerifyAzureAttestationToken(token string, providerURL string) (Report, error) {
	// Ensure providerURL uses HTTPS.
	uri, err := attestation.ParseHTTPS(providerURL)
	if err != nil {
		return Report{}, err
	}
	report, err := attestation.VerifyAzureAttestationToken(token, uri)
	if err != nil {
		return Report{}, err
	}
	return Report{
		Data:            report.Data,
		SecurityVersion: report.SecurityVersion,
		Debug:           report.Debug,
		UniqueID:        report.UniqueID,
		SignerID:        report.SignerID,
		ProductID:       report.ProductID}, nil
}
