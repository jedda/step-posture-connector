package jamf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/jedda/step-posture-connector/internal/shared"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

type Provider struct {
}

// Client defines a basic struct used by the provider to store it's API config, token & expiry time
type Client struct {
	baseUrl, clientId, clientSecret string
	timeout                         time.Duration
	token                           JamfAPIAuthToken
	tokenExpiry                     *time.Time
}

// JamfAPIAuthToken defines the JSON format returned from /api/oauth/token (Jamf API)
type JamfAPIAuthToken struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// JamfClassicMobileDevice defines the JSON format returned from /JSSResource/mobiledevices/serialnumber/%s (Jamf API)
type JamfClassicMobileDevice struct {
	MobileDevice struct {
		General struct {
			UDID         string `json:"udid"`
			Name         string `json:"device_name"`
			SerialNumber string `json:"serial_number"`
		} `json:"general"`
		Location struct {
			Username     string `json:"username"`
			RealName     string `json:"realname"`
			EmailAddress string `json:"email_address"`
			Position     string `json:"position"`
			Department   string `json:"department"`
		} `json:"location"`
		MobileDeviceGroups []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"mobile_device_groups"`
	} `json:"mobile_device"`
}

// JamfClassicComputer defines the JSON format returned from /JSSResource/computers/serialnumber/%s (Jamf API)
type JamfClassicComputer struct {
	Computer struct {
		General struct {
			UDID         string `json:"udid"`
			Name         string `json:"name"`
			SerialNumber string `json:"serial_number"`
		} `json:"general"`
		Location struct {
			Username     string `json:"username"`
			RealName     string `json:"realname"`
			EmailAddress string `json:"email_address"`
			Position     string `json:"position"`
			Department   string `json:"department"`
		} `json:"location"`
		GroupsAccounts struct {
			ComputerGroupMemberships []string `json:"computer_group_memberships"`
		} `json:"groups_accounts"`
	} `json:"computer"`
}

var client Client
var validate *validator.Validate
var config map[string]interface{}

// Bootstrap is a public function that is implemented as part of the Provider interface
// It is responsible for setting up and testing the provider then letting the main package
// know about any errors or issues that have stopped a provider bootstrapping correctly
func (p Provider) Bootstrap() error {
	validate = validator.New(validator.WithRequiredStructEnabled())
	config = map[string]interface{}{
		"JAMF_BASE_URL":        os.Getenv("JAMF_BASE_URL"),
		"JAMF_CLIENT_ID":       os.Getenv("JAMF_CLIENT_ID"),
		"JAMF_CLIENT_SECRET":   os.Getenv("JAMF_CLIENT_SECRET"),
		"JAMF_DEVICE_GROUP":    os.Getenv("JAMF_DEVICE_GROUP"),
		"JAMF_COMPUTER_GROUP":  os.Getenv("JAMF_COMPUTER_GROUP"),
		"JAMF_DEVICE_ENRICH":   os.Getenv("JAMF_DEVICE_ENRICH"),
		"JAMF_COMPUTER_ENRICH": os.Getenv("JAMF_COMPUTER_ENRICH"),
		"TIMEOUT":              os.Getenv("TIMEOUT"),
	}
	rules := map[string]interface{}{
		"JAMF_BASE_URL":        "required,url",
		"JAMF_CLIENT_ID":       "required,uuid",
		"JAMF_CLIENT_SECRET":   "required",
		"JAMF_DEVICE_GROUP":    "omitempty",
		"JAMF_COMPUTER_GROUP":  "omitempty",
		"JAMF_DEVICE_ENRICH":   "omitempty,oneof=0 1",
		"JAMF_COMPUTER_ENRICH": "omitempty,oneof=0 1",
		"TIMEOUT":              "omitempty,number,max=2",
	}
	errs := validate.ValidateMap(config, rules)
	if len(errs) > 0 {
		return fmt.Errorf("Jamf failed to bootstrap due to invalid config: %s", errs)
	}
	var timeout time.Duration
	timeoutConfig, timeoutErr := strconv.ParseInt(config["TIMEOUT"].(string), 10, 32)
	if timeoutErr != nil {
		timeout = time.Duration(10)
	} else {
		timeout = time.Duration(timeoutConfig)
	}
	shared.WriteLog(fmt.Sprintf("Jamf timeout set as %d second", timeout), 1, 0)
	// instantiate Client
	client = Client{
		baseUrl:      config["JAMF_BASE_URL"].(string),
		clientId:     config["JAMF_CLIENT_ID"].(string),
		clientSecret: config["JAMF_CLIENT_SECRET"].(string),
		timeout:      timeout,
	}
	if err := client.refreshAuthToken(); err != nil {
		return fmt.Errorf("failed to authenticate to Jamf API: %s", err)
	}
	shared.WriteLog("Jamf successfully bootstrapped and ready", 0, 0)
	return nil
}

// Handler is a public function that is implemented as part of the Provider interface
// It is responsible for handling an individual webhook request and returning StepResponseData
func (p Provider) Handler(handlerMode string, stepInputData shared.StepAttestationRequestData) (shared.StepResponseData, error) {

	// for Jamf, we have two device types
	// - Mobile Devices (iOS/iPad/iPhone)
	// - Computers (Macs)
	// we need to know the device type coming in as they have different API endpoints
	// thus, the handlerMode string on this method as either "mobiledevice" or "computer"

	deviceGroup, ok := config["JAMF_DEVICE_GROUP"].(string)
	if !ok {
		deviceGroup = ""
	}
	computerGroup, ok := config["JAMF_COMPUTER_GROUP"].(string)
	if !ok {
		computerGroup = ""
	}
	deviceEnrich, _ := strconv.ParseBool(config["JAMF_DEVICE_ENRICH"].(string))
	computerEnrich, _ := strconv.ParseBool(config["JAMF_DEVICE_ENRICH"].(string))

	// default handlerMode to mobiledevice
	if handlerMode == "" {
		handlerMode = "mobiledevice"
	}
	err := validate.Var(handlerMode, "required,oneof=computer mobiledevice")
	if err != nil {
		return shared.StepResponseData{Allow: false}, fmt.Errorf("invalid handler type: %s", err)
	}

	// validate our attestation data
	validateErr := validateAttestData(stepInputData)
	if validateErr != nil {
		return shared.StepResponseData{Allow: false}, validateErr
	}

	// grab our response from jamf pro's API
	response, err := client.doGet(fmt.Sprintf("/JSSResource/%ss/serialnumber/%s", handlerMode, stepInputData.AttestationData.PermanentIdentifier))
	if err != nil {
		if err.Error() == "404" {
			return shared.StepResponseData{Allow: false}, fmt.Errorf("serial number not found/enrolled (404 on \"/JSSResource/%ss/serialnumber/%s\")", handlerMode, stepInputData.AttestationData.PermanentIdentifier)
		} else {
			return shared.StepResponseData{Allow: false}, fmt.Errorf("error whilst communicating with Jamf API: %s", err)
		}
	}

	var mobileDevice JamfClassicMobileDevice
	var computer JamfClassicComputer

	var unmarshalErr error
	if handlerMode == "mobiledevice" {
		unmarshalErr = json.Unmarshal(response, &mobileDevice)
	} else if handlerMode == "computer" {
		unmarshalErr = json.Unmarshal(response, &computer)
	}
	if unmarshalErr != nil {
		return shared.StepResponseData{Allow: false}, fmt.Errorf("error fwhen unmarsalling Jamf API JSON: %s", unmarshalErr)
	}
	if handlerMode == "mobiledevice" {
		shared.WriteLog(fmt.Sprintf("Mobile device record %s has been matched for serial number %s", mobileDevice.MobileDevice.General.UDID, stepInputData.AttestationData.PermanentIdentifier), 1, 0)
	} else if handlerMode == "computer" {
		shared.WriteLog(fmt.Sprintf("Computer record %s has been matched for serial number %s", computer.Computer.General.UDID, stepInputData.AttestationData.PermanentIdentifier), 1, 0)
	}
	// do we need to match to a compliance group?
	var groupMatch bool
	var groups []string
	if handlerMode == "mobiledevice" && deviceGroup != "" {
		for i := range mobileDevice.MobileDevice.MobileDeviceGroups {
			groups = append(groups, mobileDevice.MobileDevice.MobileDeviceGroups[i].Name)
			if mobileDevice.MobileDevice.MobileDeviceGroups[i].Name == deviceGroup {
				groupMatch = true
				shared.WriteLog(fmt.Sprintf("Mobile device record %s is a member of \"%s\"", mobileDevice.MobileDevice.General.UDID, deviceGroup), 1, 0)
			}
		}
	}
	if handlerMode == "computer" && computerGroup != "" {
		for i := range computer.Computer.GroupsAccounts.ComputerGroupMemberships {
			groups = append(groups, computer.Computer.GroupsAccounts.ComputerGroupMemberships[i])
			if computer.Computer.GroupsAccounts.ComputerGroupMemberships[i] == computerGroup {
				groupMatch = true
				shared.WriteLog(fmt.Sprintf("Computer device record %s is a member of \"%s\"", computer.Computer.General.UDID, computerGroup), 1, 0)
			}
		}
	}
	if deviceGroup != "" && !groupMatch && handlerMode == "mobiledevice" {
		return shared.StepResponseData{Allow: false}, fmt.Errorf("%s is not a member of supplied compliance group \"%s\"", stepInputData.AttestationData.PermanentIdentifier, deviceGroup)
	} else if computerGroup != "" && !groupMatch && handlerMode == "computer" {
		return shared.StepResponseData{Allow: false}, fmt.Errorf("%s is not a member of supplied compliance group \"%s\"", stepInputData.AttestationData.PermanentIdentifier, computerGroup)
	}

	var enrichData map[string]interface{}
	if deviceEnrich && handlerMode == "mobiledevice" {
		enrichData = map[string]interface{}{"device": map[string]interface{}{"udid": mobileDevice.MobileDevice.General.UDID, "serial_number": mobileDevice.MobileDevice.General.SerialNumber, "name": mobileDevice.MobileDevice.General.Name}, "user": map[string]interface{}{"username": mobileDevice.MobileDevice.Location.Username, "realname": mobileDevice.MobileDevice.Location.RealName, "email_address": mobileDevice.MobileDevice.Location.EmailAddress, "position": mobileDevice.MobileDevice.Location.Position, "department": mobileDevice.MobileDevice.Location.Department}, "groups": groups}
	} else if computerEnrich && handlerMode == "computer" {
		enrichData = map[string]interface{}{"device": map[string]interface{}{"udid": computer.Computer.General.UDID, "serial_number": computer.Computer.General.SerialNumber, "name": computer.Computer.General.Name}, "user": map[string]interface{}{"username": computer.Computer.Location.Username, "realname": computer.Computer.Location.RealName, "email_address": computer.Computer.Location.EmailAddress, "position": computer.Computer.Location.Position, "department": computer.Computer.Location.Department}, "groups": groups}
	}

	if deviceEnrich || computerEnrich {
		return shared.StepResponseData{Allow: true, Data: enrichData}, nil
	} else {
		return shared.StepResponseData{Allow: true}, nil
	}
}

// refreshAuthToken is a private function that is responsible for handling check & refresh
// of the bearer token to be used with Jamf Pro's API. If an error is found it is returned
// and this will chain back up to a webhook deny response.
func (client *Client) refreshAuthToken() error {
	// check if we have a current token and it's validity window is open
	if client.tokenExpiry != nil && client.tokenExpiry.After(time.Now()) {
		// token should be valid
		shared.WriteLog(fmt.Sprintf("Jamf auth token is valid until %s - no need to refresh", client.tokenExpiry), 1, 0)
		return nil
	}
	// setup the auth form and POST to Jamf API
	httpClient := &http.Client{
		Timeout: time.Second * client.timeout,
	}
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.clientId},
		"client_secret": {client.clientSecret},
	}
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/api/oauth/token", client.baseUrl), bytes.NewBufferString(data.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	if err != nil {
		return err
	}
	response, err := httpClient.Do(request)
	shared.WriteLog(fmt.Sprintf("Response from %s/api/oauth/token %+v", client.baseUrl, response), 2, 0)

	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("%s", body)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		panic(err.Error())
	}
	var authToken JamfAPIAuthToken
	unmarshalErr := json.Unmarshal(body, &authToken)
	if unmarshalErr != nil {
		return fmt.Errorf("error fwhen unmarsalling json: %s", unmarshalErr)
	}

	// need to do more error checking here
	expiry := time.Now().Add(time.Duration(authToken.ExpiresIn) * time.Second)
	client.tokenExpiry = &expiry
	client.token = authToken
	shared.WriteLog(fmt.Sprintf("Successfully refreshed Jamf API token. Will expire %s", expiry), 1, 0)
	return nil
}

// refreshAuthToken is a private function that is responsible for handling a HTTP GET
// from Jamf Pro's API. If an error is found it is returned and this will chain back up
// to a webhook deny response.
func (client *Client) doGet(uri string) ([]byte, error) {
	// TODO implement https://pkg.go.dev/net/http/httptrace as a debug thing
	shared.WriteLog(fmt.Sprintf("Have been asked to GET %s/%s", client.baseUrl, uri), 2, 0)
	// refresh token if required
	err := client.refreshAuthToken()
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{
		Timeout: time.Second * client.timeout,
	}
	request, err := http.NewRequest("GET", client.baseUrl+uri, nil)
	if err != nil {
		return nil, fmt.Errorf("%s", err.Error())
	}
	request.Header.Add("accept", "application/json")
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", client.token.AccessToken))
	response, err := httpClient.Do(request)
	shared.WriteLog(fmt.Sprintf("Response from %s/api/oauth/token %+v", client.baseUrl, response), 2, 0)
	if err != nil {
		return nil, fmt.Errorf("%s", err.Error())
	}
	if response.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("404")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d on GET (%s)", response.StatusCode, client.baseUrl+uri)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s", err.Error())
	}
	return body, nil
}

// validateAttestData is a private function that is responsible for any additional
// validation prior to asking Jamf. Currently it ensures a device serial number can be
// validated against known formats. If an error is found it is returned and this will
// chain back up to a webhook deny response.
func validateAttestData(stepInputData shared.StepAttestationRequestData) error {
	errs := validate.Var(stepInputData.AttestationData.PermanentIdentifier, "required,alphanum,min=8,max=14")
	if errs != nil {
		return fmt.Errorf("serial number did not pass validation: %s", errs)
	}
	return nil
}
