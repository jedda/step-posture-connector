package file

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/jedda/step-posture-connector/internal/shared"
	"io"
	"os"
	"strings"
)

type Provider struct {
}

// Data defines a holding struct for device data parsed from a file
type Data struct {
	Devices []Device `json:"devices"`
}

// Device defines an individual device struct parsed from a file
type Device struct {
	Identifier string                 `json:"identifier"`
	Data       map[string]interface{} `json:"data"`
}

var validate *validator.Validate
var config map[string]interface{}
var data Data

// Bootstrap is a public function that is implemented as part of the Provider interface
// It is responsible for setting up and testing the provider then letting the main package
// know about any errors or issues that have stopped a provider bootstrapping correctly
func (p Provider) Bootstrap() error {
	validate = validator.New(validator.WithRequiredStructEnabled())
	config = map[string]interface{}{
		"FILE_PATH": os.Getenv("FILE_PATH"),
		"FILE_TYPE": os.Getenv("FILE_TYPE"),
	}
	rules := map[string]interface{}{
		"FILE_PATH": "required,file",
		"FILE_TYPE": "required,oneof=json csv",
	}
	errs := validate.ValidateMap(config, rules)
	if len(errs) > 0 {
		return fmt.Errorf("JSON provider could not bootstrap due to invalid config: %s", errs)
	}
	file, err := os.Open(config["FILE_PATH"].(string))
	if err != nil {
		return fmt.Errorf("could not open %s for read: %s", config["FILE_PATH"].(string), err)
	}
	defer func() { _ = file.Close() }()
	if config["FILE_TYPE"] == "json" {
		jsonBytes, _ := io.ReadAll(file)
		err := parseJSON(jsonBytes)
		if err != nil {
			return err
		}
	} else if config["FILE_TYPE"] == "csv" {
		csvBytes, _ := io.ReadAll(file)
		err := parseCSV(csvBytes)
		if err != nil {
			return err
		}
	}
	shared.WriteLog(fmt.Sprintf("%d devices loaded from %s.", len(data.Devices), config["FILE_PATH"].(string)), 1, 0)
	shared.WriteLog("File provider successfully bootstrapped and ready.", 0, 0)
	return nil
}

// Handler is a public function that is implemented as part of the Provider interface
// It is responsible for handling an individual webhook request and returning StepResponseData
func (p Provider) Handler(handlerMode string, stepInputData shared.StepAttestationRequestData) (shared.StepResponseData, error) {
	for i := range data.Devices {
		if data.Devices[i].Identifier == stepInputData.AttestationData.PermanentIdentifier {
			return shared.StepResponseData{Allow: true, Data: data.Devices[i].Data}, nil
		}
	}
	return shared.StepResponseData{Allow: false}, fmt.Errorf("device identifier (%s) not matched in file", stepInputData.AttestationData.PermanentIdentifier)
}

// parseJSON is a private function that unmarshals a JSON byte slice
// and stores it in our data variable.
// it returns an error if one is encountered
func parseJSON(jsonBytes []byte) error {
	err := json.Unmarshal(jsonBytes, &data)
	if err != nil {
		return err
	}
	return nil
}

// parseCSV is a private function that reads in a CSV byte slice
// then processes headers and rows into storage in our data variable.
// it returns an error if one is encountered
func parseCSV(csvBytes []byte) error {
	csvReader := csv.NewReader(bytes.NewBuffer(csvBytes))
	csvData, err := csvReader.ReadAll()
	if err != nil {
		return err
	}
	// check for headers
	headers := csvData[0]
	if len(headers) == 0 || strings.Compare(headers[0], "Identifier") != 0 {
		return fmt.Errorf("first csv header must be Identifier: found %s", headers[0])
	}
	shared.WriteLog(fmt.Sprintf("Loaded fields from file: %+v", headers), 2, 0)
	for i := range csvData {
		if i > 0 {
			var enrichData = map[string]interface{}{}
			for o := range csvData[i] {
				if o > 0 {
					enrichData[headers[o]] = csvData[i][o]
				}
			}
			shared.WriteLog(fmt.Sprintf("Loaded device from file: %s, %+v", csvData[i][0], enrichData), 2, 0)
			data.Devices = append(data.Devices, Device{Identifier: csvData[i][0], Data: enrichData})
		}
	}
	return nil
}
