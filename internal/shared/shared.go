package shared

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"
)

var LoggingLevel int

// StepAttestationRequestData defines the structure of the incoming JSON from step-ca
// we currently only unmarshal the parts we are interested in, but this can be easily
// expanded or changed in the future
type StepAttestationRequestData struct {
	Timestamp       string `json:"timestamp"`
	AttestationData struct {
		PermanentIdentifier string `json:"permanentIdentifier"`
	} `json:"attestationData"`
	X509CertificateRequest struct {
		Raw string `json:"raw"`
	} `json:"x509CertificateRequest"`
}

// StepResponseData defines the structure of the JSON we will return to step-ca
// there is always an Allow boolean, and Data is optional.
// Data is a map[string]interface{} to allow for flexibility in the JSON returned
type StepResponseData struct {
	Allow bool                   `json:"allow"`
	Data  map[string]interface{} `json:"data,omitempty"`
}

// ValidatePEM checks either a CSR or PEM certificate block to ensure
// that it can be successfully decoded, passes very simple tests and is current.
// For valid PEMs it returns the common name, and for invalid PEMs it returns an error.
func ValidatePEM(raw string, csr bool) (string, error) {
	var pemString string
	if csr {
		pemString = fmt.Sprintf("-----BEGIN CERTIFICATE REQUEST-----\n%s\n-----END CERTIFICATE REQUEST-----", raw)
	} else {
		pemString = raw
	}
	pemBlock, _ := pem.Decode([]byte(pemString))
	if pemBlock == nil {
		return "", fmt.Errorf("failed to decode PEM data")
	}
	if csr {
		parsedCsr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
		WriteLog(fmt.Sprintf("Parsed CSR for validation: %+v", parsedCsr), 2, 0)
		if err != nil {
			return "", fmt.Errorf("failed to parse certificate request data")
		}
		if parsedCsr.Subject.CommonName == "" {
			return "", fmt.Errorf("certificate request common name is empty")
		}
		return parsedCsr.Subject.CommonName, nil
	} else {
		parsedPem, err := x509.ParseCertificate(pemBlock.Bytes)
		WriteLog(fmt.Sprintf("Parsed PEM for validation: %+v", parsedPem), 2, 0)
		if err != nil {
			return "", fmt.Errorf("failed to parse certificate request data")
		}
		if parsedPem.Subject.CommonName == "" {
			return "", fmt.Errorf("certificate request common name is empty")
		}
		if parsedPem.NotAfter.Before(time.Now()) {
			return "", fmt.Errorf("certificate has expired")
		}
		if parsedPem.NotBefore.After(time.Now()) {
			return "", fmt.Errorf("certificate not yet valid")
		}
		return parsedPem.Subject.CommonName, nil
	}
}

// WriteLog is a shared logging function that can be used right across the project.
// It supports writing to stdout using multiple colors and takes a verbosity level
// Some colors that can be used are 31-Red, 32-Green, 33-Yellow, 36-Aqua
func WriteLog(content string, level int, color int) {
	if LoggingLevel >= level {
		if color > 0 {
			log.Println(fmt.Sprintf("\x1b[%dm%s\x1b[0m", color, content))
		} else {
			log.Println(content)
		}
	}
}
