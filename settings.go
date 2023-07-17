package main

import (
	"fmt"
	"regexp"

	mapset "github.com/deckarep/golang-set"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/mailru/easyjson"
)

const invalidSettingsMessage = "Provided settings are not valid"

type Settings struct {
	DeniedLabels      mapset.Set
	ConstrainedLabels map[string]*regexp.Regexp
}

func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	return newSettings(validationReq.Settings)
}

func (s *Settings) Validate() error {
	constrainedLabels := mapset.NewThreadUnsafeSet()

	for label := range s.ConstrainedLabels {
		constrainedLabels.Add(label)
	}

	constrainedAndDenied := constrainedLabels.Intersect(s.DeniedLabels)
	if constrainedAndDenied.Cardinality() != 0 {
		return fmt.Errorf("the following labels cannot be constrained and denied at the same time: %v", constrainedAndDenied)
	}

	return nil
}

func newSettings(settingsJson []byte) (Settings, error) {
	basicSettings := BasicSettings{}
	err := easyjson.Unmarshal(settingsJson, &basicSettings)
	if err != nil {
		return Settings{}, err
	}

	deniedLabels := mapset.NewThreadUnsafeSet()
	for _, label := range basicSettings.DeniedLabels {
		deniedLabels.Add(label)
	}

	constrainedLabels := make(map[string]*regexp.Regexp)
	for name, expr := range basicSettings.ConstrainedLabels {
		reg, err := regexp.Compile(expr)
		if err != nil {
			return Settings{}, fmt.Errorf("compiling regexp %s: %w", expr, err)
		}
		constrainedLabels[name] = reg
	}

	return Settings{
		DeniedLabels:      deniedLabels,
		ConstrainedLabels: constrainedLabels,
	}, nil
}

func validateSettings(payload []byte) ([]byte, error) {
	settings, err := newSettings(payload)
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("%s: %v", invalidSettingsMessage, err)))
	}

	err = settings.Validate()
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("%s: %v", invalidSettingsMessage, err)))
	}

	return kubewarden.AcceptSettings()
}
