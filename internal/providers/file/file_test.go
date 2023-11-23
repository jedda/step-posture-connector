package file

import (
	"encoding/base64"
	"encoding/json"
	"github.com/jedda/step-posture-connector/internal/shared"
	"testing"
)

const stepRequestB64 = `ewogICAgImF0dGVzdGF0aW9uRGF0YSI6IHsKICAgICAgICAicGVybWFuZW50SWRlbnRpZmllciI6ICJDOFJZN05CTlY4RSIKICAgIH0sCiAgICAieDUwOUNlcnRpZmljYXRlUmVxdWVzdCI6IHsKICAgICAgICAicmF3IjogIk1JSUJQRENCeEFJQkFEQkZNUXN3Q1FZRFZRUUdFd0pCVlRFUk1BOEdBMVVFQ0F3SVZtbGpkRzl5YVdFeERUQUxCZ05WQkFvTUJGUmxjM1F4RkRBU0JnTlZCQU1NQzBNNFVsazNUa0pPVmpoRk1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFWExCZzdPa2JSajlYQXIxOWcrN2FGQzIxQ2lxaUREalloTWU1VjZkbzhkQTNmOFFvUTNvN3hSUXZndmY1Y04yOXdyTVBOMlc2UmVpVFBEZ1c2OEZkQlVGVkYrR1JMOWFINExncml1TzNxWlFUQ09PbmV4dElYeWxmNWJWZ3RLT2pvQUF3Q2dZSUtvWkl6ajBFQXdJRFp3QXdaQUl3Sm9jYmFRaU8vUHNlaUJ2dkd4K2xyem5yeSt4OEs4amcrMlZVckczYlRTYXRIMlBoRllnNXlobUYwQkpkaTNUa0FqQjdDYmVLK1RCY3VDc3RnejNKUVBTY2lqRjYyZ0JmS2syOTE2WFdXTFdZR0ppOEluQTcxYVZaVWZQME9DYlBveW89IgogICAgfQp9`

func TestParseJSONValid(t *testing.T) {
	data = Data{}
	b64Data := decodeB64(t, `eyAiZGV2aWNlcyI6WwogIHsKICAgICJpZGVudGlmaWVyIjogIkM4Ulk3TkJOVjhFIiwKICAgICJkYXRhIjogewogICAgICAidXNlcm5hbWUiOiAiZnJhbmsuam9uZXMiCiAgICB9CiAgfSwKICB7CiAgICAiaWRlbnRpZmllciI6ICJDNlJZWVZCTjIxMiIKICB9Cl19`)
	parseErr := parseJSON(b64Data)
	if parseErr != nil {
		t.Fatalf("JSON parse error: %s", parseErr)
	}
	if len(data.Devices) != 2 {
		t.Fatalf("Expecting 2 loaded devices. Got %d.", len(data.Devices))
	}
}

func TestParseJSONInvalid(t *testing.T) {
	data = Data{}
	b64Data := decodeB64(t, `eyJkZXZpY2VzIjpbeyAiaWRlbnRpZmllciI6Ik8yVERWU0lSUVUifSxdfQ==`)
	parseErr := parseJSON(b64Data)
	if parseErr == nil {
		t.Fatal("Should have errored on invalid JSON")
	}
}

func TestParseCSVValid(t *testing.T) {
	data = Data{}
	b64Data := decodeB64(t, `SWRlbnRpZmllcixVc2VybmFtZSxEZXBhcnRtZW50CkcyUk00NUNNUkMsZnJhbmsuam9uZXMsU2FsZXMKQzhSWTdOQk5WOEUsc2lhbi5zbWl0aCxFbmdpbmVlcmluZw==`)
	parseErr := parseCSV(b64Data)
	if parseErr != nil {
		t.Fatalf("CSV parse error: %s", parseErr)
	}
	if len(data.Devices) != 2 {
		t.Fatalf("Expecting 2 loaded devices. Got %d.", len(data.Devices))
	}
}

func TestParseCSVMissingIdentifier(t *testing.T) {
	data = Data{}
	b64Data := decodeB64(t, `U2VyaWFsTnVtYmVyCkYzTlZaMjY1TFgKM1BPQkhQVEcyUwpHR1JUWlZEQUZQCldGQjhMNUJXRFIKV0c3STUxWjk5OA==`)
	parseErr := parseCSV(b64Data)
	if parseErr == nil {
		t.Fatal("Should have errored on missing Identifier")
	}
}

func TestParseCSVInvalid(t *testing.T) {
	data = Data{}
	b64Data := decodeB64(t, `SWRlbnRpZmllcixVc2VybmFtZQpHMlJNNDVDTVJDLGZyYW5rLmpvbmVzLEludmFsaWQKRzI3WTQ4Q1Q0QixzaWFuLnNtaXRoLEludmFsaWQ=`)
	parseErr := parseCSV(b64Data)
	if parseErr == nil {
		t.Fatal("Should have errored on invalid CSV")
	}
}

func TestJSONAttest(t *testing.T) {
	p := Provider{}
	stepRequest := shared.StepAttestationRequestData{}
	// first parse and load devices from JSON
	TestParseJSONValid(t)
	b64Data := decodeB64(t, stepRequestB64)
	err := json.Unmarshal(b64Data, &stepRequest)
	if err != nil {
		t.Fatalf("Could not unmarshal example step request: %s ", err)
	}
	resp, err := p.Handler("deviceAttest", stepRequest)
	if err != nil {
		t.Fatalf("Handler error: %s", err)
	}
	if resp.Allow == false {
		t.Fatalf("Device should have been allowed!")
	}
}

func TestCSVAttest(t *testing.T) {
	p := Provider{}
	stepRequest := shared.StepAttestationRequestData{}
	// first parse and load devices from JSON
	TestParseCSVValid(t)
	b64Data := decodeB64(t, stepRequestB64)
	err := json.Unmarshal(b64Data, &stepRequest)
	if err != nil {
		t.Fatalf("Could not unmarshal example step request: %s ", err)
	}
	resp, err := p.Handler("deviceAttest", stepRequest)
	if err != nil {
		t.Fatalf("Handler error: %s", err)
	}
	if resp.Allow == false {
		t.Fatalf("Device should have been allowed!")
	}
}

func decodeB64(t *testing.T, b64String string) []byte {
	b64Data := make([]byte, base64.StdEncoding.DecodedLen(len(b64String)))
	_, decodeErr := base64.StdEncoding.Decode(b64Data, []byte(b64String))
	if decodeErr != nil {
		t.Fatalf("Base64 decode error: %s", decodeErr)
	}
	return b64Data
}
