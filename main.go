package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/jedda/step-posture-connector/internal/providers/file"
	"github.com/jedda/step-posture-connector/internal/providers/jamf"
	"github.com/jedda/step-posture-connector/internal/shared"
	"github.com/joho/godotenv"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const version string = "1.0.0"

var validate *validator.Validate
var provider ProviderInterface
var config map[string]interface{}
var webhooks map[string]string

// ProviderInterface defines the function signatures that a provider must implement
type ProviderInterface interface {
	Bootstrap() error
	Handler(string, shared.StepAttestationRequestData) (shared.StepResponseData, error)
}

// main execution function. validates config and bootstraps provider
// prior to starting HTTPS webhook server
func main() {
	shared.WriteLog(fmt.Sprintf("Step Posture Connector v%s", version), 0, 36)
	shared.WriteLog("by Jedda Wignall <oss@jedda.me>", 0, 36)
	shared.WriteLog("For information & documentation, see https://github.com/jedda/step-posture-connector", 0, 36)

	// instantiate our global validator
	validate = validator.New(validator.WithRequiredStructEnabled())
	// attempt to load environment variables from a .env file
	envErr := godotenv.Load()
	if envErr != nil {
		shared.WriteLog(fmt.Sprintf(".env was not loaded: %s", envErr), 0, 0)
	}
	// read in our config from env variables and validate
	config = map[string]interface{}{
		"LOGGING_LEVEL":   os.Getenv("LOGGING_LEVEL"),
		"PORT":            os.Getenv("PORT"),
		"PROVIDER":        os.Getenv("PROVIDER"),
		"TLS_CERT_PATH":   os.Getenv("TLS_CERT_PATH"),
		"TLS_KEY_PATH":    os.Getenv("TLS_KEY_PATH"),
		"TLS_CA_PATH":     os.Getenv("TLS_CA_PATH"),
		"ENABLE_MTLS":     os.Getenv("ENABLE_MTLS"),
		"WEBHOOK_IDS":     os.Getenv("WEBHOOK_IDS"),
		"WEBHOOK_SECRETS": os.Getenv("WEBHOOK_SECRETS"),
	}
	configRules := map[string]interface{}{
		"LOGGING_LEVEL":   "omitempty,oneof=0 1 2",
		"PORT":            "omitempty,number",
		"PROVIDER":        "required,oneof=file jamf",
		"TLS_CERT_PATH":   "required,file",
		"TLS_KEY_PATH":    "required,file",
		"TLS_CA_PATH":     "omitempty,file",
		"ENABLE_MTLS":     "omitempty,oneof=0 1",
		"WEBHOOK_IDS":     "required",
		"WEBHOOK_SECRETS": "required",
	}
	errs := validate.ValidateMap(config, configRules)
	if len(errs) > 0 {
		shared.WriteLog(fmt.Sprintf("Failed to start due to invalid config: %s", errs), 0, 33)
		os.Exit(1)
	}

	// set our LOGGING_LEVEL variable from config
	loggingLevel, ok := config["LOGGING_LEVEL"].(string)
	if ok {
		shared.LoggingLevel, _ = strconv.Atoi(loggingLevel)
	}
	shared.WriteLog("Verbose logging enabled", 1, 0)
	shared.WriteLog("Debug logging enabled", 2, 0)

	// initialise our provider and ensure it complies with ProviderInterface
	providerName := config["PROVIDER"].(string)
	if providerName == "file" {
		provider = file.Provider{}
	} else if providerName == "jamf" {
		provider = jamf.Provider{}
	}
	_, providerOk := provider.(ProviderInterface)
	if !providerOk {
		shared.WriteLog(fmt.Sprintf("Failed to initialise provider \"%s\".", errs), 1, 33)
		os.Exit(1)
	}

	// bootstrap our provider
	err := provider.Bootstrap()
	if err != nil {
		shared.WriteLog(fmt.Sprintf("Failed to bootstrap provider \"%s\": %s", providerName, err), 0, 33)
		os.Exit(1)
	}

	// put our webhook ids and secrets into a map and initialise our handlers
	ids := strings.Split(config["WEBHOOK_IDS"].(string), ",")
	secrets := strings.Split(config["WEBHOOK_SECRETS"].(string), ",")
	if len(ids) != len(secrets) {
		shared.WriteLog(fmt.Sprintf("Mismatched number of webhook IDs and secrets. Cannot initialise."), 1, 33)
		os.Exit(1)
	}
	webhooks = make(map[string]string)
	for i := range ids {
		idErr := validate.Var(ids[i], "required,uuid")
		secretErr := validate.Var(secrets[i], "required,base64")
		if idErr == nil && secretErr == nil {
			webhooks[ids[i]] = secrets[i]
			shared.WriteLog(fmt.Sprintf("Initialised a handler & stored secret for webhook ID %s", ids[i]), 0, 0)

		} else {
			shared.WriteLog(fmt.Sprintf("Webhook ID or it's secret failed validation: %s, %s, %s", ids[i], idErr, secretErr), 1, 33)
			os.Exit(1)
		}
	}

	http.HandleFunc("/webhook/device-attest", webhookHandlerAttestDevice)

	// configure our TLS settings
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	// are we enabling mutual TLS?
	mtlsConfig, mtlsErr := strconv.ParseBool(config["ENABLE_MTLS"].(string))
	if mtlsErr != nil {
		mtlsConfig = false
	}
	if mtlsConfig {
		caCert, err := os.ReadFile(config["TLS_CA_PATH"].(string))
		if err != nil {
			shared.WriteLog(fmt.Sprintf("Failed to load CA from TLS_CA_PATH: %s", err), 0, 33)
			os.Exit(1)
		}
		caCn, err := shared.ValidatePEM(string(caCert), false)
		if err != nil {
			shared.WriteLog(fmt.Sprintf("Failed to validate CA for mTLS: %s", err), 0, 33)
			os.Exit(1)
		}
		shared.WriteLog(fmt.Sprintf("Mutual TLS CA loaded: %s", caCn), 1, 0)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		shared.WriteLog(fmt.Sprintf("Mutual TLS enabled"), 0, 0)
	}
	port, ok := config["PORT"].(string)
	if !ok {
		port = "9443" // default port 9443
	}
	server := &http.Server{
		Addr:      fmt.Sprintf(":%s", port),
		TLSConfig: tlsConfig,
	}
	// validate our local server TLS certificate
	caCert, err := os.ReadFile(config["TLS_CERT_PATH"].(string))
	if err != nil {
		shared.WriteLog(fmt.Sprintf("Failed to load local server TLS certificate from %s: %s", config["TLS_CERT_PATH"].(string), err), 0, 33)
		os.Exit(1)
	}
	tlsCn, err := shared.ValidatePEM(string(caCert), false)
	if err != nil {
		shared.WriteLog(fmt.Sprintf("Failed to validate local server TLS certificate: %s", err), 0, 33)
		os.Exit(1)
	}
	shared.WriteLog(fmt.Sprintf("TLS certificate loaded: %s", tlsCn), 1, 0)
	shared.WriteLog(fmt.Sprintf("Webhook listener starting on port :%s", port), 0, 0)
	if err := server.ListenAndServeTLS(config["TLS_CERT_PATH"].(string), config["TLS_KEY_PATH"].(string)); err != nil {
		shared.WriteLog(fmt.Sprintf("Failed to start webhook server :%d", err), 0, 33)
		os.Exit(1)
	}
}

// webhookHandlerAttestDevice is a private function that serves as the primary handler
// for incoming webhooks. it handles authentication and validation of the request before
// handing off an appropriate request to the provider. it then performs some final error
// handling before returning the decision to step-ca
func webhookHandlerAttestDevice(w http.ResponseWriter, r *http.Request) {
	handlerMode := r.URL.Query().Get("mode")
	shared.WriteLog(fmt.Sprintf("Recieved a new webhook request for %s (mode=%s)", r.URL.Path, handlerMode), 2, 0)
	// authenticate the incoming request using step-ca signature
	body, authErr := authenticateRequest(r)
	if authErr != nil {
		shared.WriteLog(fmt.Sprintf("[DENY] Failed to authenticate request: %s", authErr), 0, 31)
		deny(w, http.StatusUnauthorized)
		return
	}
	// decode the incoming request JSON body into a StepAttestationRequestData struct
	var stepInputData shared.StepAttestationRequestData
	parseErr := json.NewDecoder(bytes.NewReader(body)).Decode(&stepInputData)
	if parseErr != nil {
		shared.WriteLog(fmt.Sprintf("[DENY] Failed to parse request: %s", parseErr), 0, 31)
		deny(w, http.StatusBadRequest)
		return
	}
	// validate the data prior to processing
	validErr := validateRequest(stepInputData)
	if validErr != nil {
		shared.WriteLog(fmt.Sprintf("[DENY] Failed to validate request: %s", validErr), 0, 31)
		deny(w, http.StatusBadRequest)
		return
	}
	// make the request to the provider
	response, err := provider.Handler(handlerMode, stepInputData)

	// deny the request on any error
	if err != nil {
		shared.WriteLog(fmt.Sprintf("[DENY] %s", err), 0, 31)
		deny(w, http.StatusBadRequest)
		return
	}

	// double check that the request was allowed
	if response.Allow == true {
		responseJSON, err := json.Marshal(response)
		if err != nil {
			shared.WriteLog(fmt.Sprintf("[DENY] Failed to marshal JSON response: %s", err), 0, 31)
			deny(w, http.StatusInternalServerError)
		}
		if response.Data != nil {
			shared.WriteLog(fmt.Sprintf("Returning enrichment data for identifier %s: %s", stepInputData.AttestationData.PermanentIdentifier, string(responseJSON)), 1, 0)
		}
		shared.WriteLog(fmt.Sprintf("[ALLOW] Request was allowed for identifier %s", stepInputData.AttestationData.PermanentIdentifier), 0, 32)
		allow(w, response)
		return
	} else {
		// would be unlikely to get here - denials should come with an error
		// but just in case this ever happens we will return an implicit deny
		shared.WriteLog("[DENY] Request denied.", 0, 31)
		deny(w, http.StatusBadRequest)
		return
	}
}

// validateRequest is a private function that validates an incoming webhook
// request. this happens post authentication, and performs some checks on the
// submitted request including validation of the X.509 CSR data and attestation
// identifiers. if validation fails, it returns an error.
func validateRequest(stepInputData shared.StepAttestationRequestData) error {
	// parse the timestamp from the request
	ts, err := time.Parse(time.RFC3339, stepInputData.Timestamp)
	if err != nil {
		return fmt.Errorf("failed to parse request timestamp: %s - %s", err, stepInputData.Timestamp)
	}
	// to ensure no replay, we check the timestamp is within the last 10 seconds
	if time.Since(ts) > time.Duration(10)*time.Second {
		return fmt.Errorf("request aged over 10 seconds: %s", stepInputData.Timestamp)
	}
	commonName, err := shared.ValidatePEM(stepInputData.X509CertificateRequest.Raw, true)
	if err != nil {
		return fmt.Errorf("failed to validate CSR: %s", err)
	}
	shared.WriteLog(fmt.Sprintf("Will validate request for certificate (CN=%s).", commonName), 1, 0)
	// check to ensure that we have a permanentIdentifier (serial number)
	if stepInputData.AttestationData.PermanentIdentifier == "" {
		return fmt.Errorf("recieved a request without a permanentIdentifier in attestationData")
	}
	// check to ensure that the permanentIdentifier is set as the commonName
	// step-ca already enforces this, but lets double check just in case
	if stepInputData.AttestationData.PermanentIdentifier != commonName {
		return fmt.Errorf("common name does not match permanentIdentifier")
	}
	return nil
}

// authenticateRequest is a private function that checks and authenticates an
// incoming webhook request using step-ca's headers and HMAC signature.
// for valid, authenticated hooks it returns a byte slice of the request body,
// and for failures it returns an error
func authenticateRequest(r *http.Request) ([]byte, error) {
	if r.Method != "POST" {
		return nil, fmt.Errorf("ignoring a %s request as we only accept POST", r.Method)
	}
	// check for webhook id in HTTP header X-Smallstep-Webhook-ID
	id := r.Header.Get("X-Smallstep-Webhook-ID")
	if id == "" {
		return nil, fmt.Errorf("missing X-Smallstep-Webhook-ID header")
	}
	// check for signature in HTTP header X-Smallstep-Signature then decode
	rawSig := r.Header.Get("X-Smallstep-Signature")
	if rawSig == "" {
		return nil, fmt.Errorf("missing X-Smallstep-Signature-ID header")
	}
	sig, err := hex.DecodeString(rawSig)
	if err != nil {
		return nil, fmt.Errorf("invalid X-Smallstep-Webhook-ID header: %s", err)
	}
	// get the webhook request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read webhook body: %s", err)
	}
	// decode our signing secret
	sigSecret, err := base64.StdEncoding.DecodeString(webhooks[id])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signing secret for webhook %s: %s", id, err)
	}
	// verify the signed request
	hm := hmac.New(sha256.New, sigSecret)
	hm.Write(body)
	mac := hm.Sum(nil)
	if ok := hmac.Equal(sig, mac); !ok {
		return nil, fmt.Errorf("invalid signature for incoming webhook %s", id)
	}
	shared.WriteLog(fmt.Sprintf("Successfully authenticated & confirmed signature of webhook ID %s.", id), 1, 0)
	return body, nil
}

// deny is a private function that writes a denial to the http response
// with a specific status code. it is used as part of errors or denials
// and will exit fatally if the response cannot be marshaled as json
func deny(w http.ResponseWriter, s int) {
	deny := shared.StepResponseData{Allow: false}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(s)
	err := json.NewEncoder(w).Encode(deny)
	if err != nil {
		shared.WriteLog(fmt.Sprintf("error when encoding json: %s.", err), 1, 33)
		os.Exit(1)
	}
	return
}

// allow is a private function that writes a allow to the http response
// along with any included enrichment data. it will exit fatally
// if the response cannot be marshaled as json
func allow(w http.ResponseWriter, data shared.StepResponseData) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		shared.WriteLog(fmt.Sprintf("error when encoding json: %s.", err), 1, 33)
		os.Exit(1)
	}
	return
}
