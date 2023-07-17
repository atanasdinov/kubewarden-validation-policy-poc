package main

import (
	"testing"

	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/mailru/easyjson"
)

func TestParseValidSettings(t *testing.T) {
	settingsJSON := []byte(`
        {
            "denied_labels": [ "foo", "bar" ],
            "constrained_labels": {
                    "cost-center": "cc-\\d+"
            }
        }`)

	settings, err := newSettings(settingsJSON)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	expectedDeniedLabels := []string{"foo", "bar"}
	for _, exp := range expectedDeniedLabels {
		if !settings.DeniedLabels.Contains(exp) {
			t.Errorf("Missing value %s", exp)
		}
	}

	re, found := settings.ConstrainedLabels["cost-center"]
	if !found {
		t.Error("Didn't find the expected constrained label")
	}

	expectedRegexp := `cc-\d+`
	if re.String() != expectedRegexp {
		t.Errorf("Expected regexp to be %v - got %v instead",
			expectedRegexp, re.String())
	}
}

func TestParseSettingsWithInvalidRegexp(t *testing.T) {
	settingsJSON := []byte(`
        {
            "denied_labels": [ "foo", "bar" ],
            "constrained_labels": {
                    "cost-center": "cc-[a+"
            }
        }`)

	_, err := newSettings(settingsJSON)
	if err == nil {
		t.Errorf("Didn't get expected error")
	}
}

func TestDetectValidSettings(t *testing.T) {
	settingsJSON := []byte(`
    {
        "denied_labels": [ "foo", "bar" ],
        "constrained_labels": {
            "cost-center": "cc-\\d+"
        }
    }`)

	responsePayload, err := validateSettings(settingsJSON)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	var response kubewarden_protocol.SettingsValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if !response.Valid {
		t.Errorf("Expected settings to be valid: %s", *response.Message)
	}
}

func TestDetectNotValidSettingsDueToBrokenRegexp(t *testing.T) {
	settingsJSON := []byte(`
    {
        "denied_labels": [ "foo", "bar" ],
        "constrained_labels": {
            "cost-center": "cc-[a+"
        }
    }
    `)

	responsePayload, err := validateSettings(settingsJSON)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	var response kubewarden_protocol.SettingsValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Valid {
		t.Error("Expected settings to not be valid")
	}

	if *response.Message != "Provided settings are not valid: compiling regexp cc-[a+: error parsing regexp: missing closing ]: `[a+`" {
		t.Errorf("Unexpected validation error message: %s", *response.Message)
	}
}

func TestDetectNotValidSettingsDueToConflictingLabels(t *testing.T) {
	settingsJSON := []byte(`
    {
        "denied_labels": [ "foo", "bar", "cost-center" ],
        "constrained_labels": {
            "cost-center": ".*"
        }
    }`)
	responsePayload, err := validateSettings(settingsJSON)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	var response kubewarden_protocol.SettingsValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Valid {
		t.Error("Expected settings to not be valid")
	}

	if *response.Message != "Provided settings are not valid: the following labels cannot be constrained and denied at the same time: Set{cost-center}" {
		t.Errorf("Unexpected validation error message: %s", *response.Message)
	}
}
