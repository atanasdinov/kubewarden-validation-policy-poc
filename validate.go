package main

import (
	"fmt"

	"github.com/francoispqt/onelog"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/mailru/easyjson"
)

func validate(payload []byte) ([]byte, error) {
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := easyjson.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(
				fmt.Sprintf("unmarshaling validation request: %s", err.Error())),
			kubewarden.Code(400))
	}

	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(
				fmt.Sprintf("unmarshaling policy settings: %s", err.Error())),
			kubewarden.Code(400))
	}

	var pod corev1.Pod
	if err = easyjson.Unmarshal(validationRequest.Request.Object, &pod); err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(
				fmt.Sprintf("unmarshaling Pod object: %s", err.Error())),
			kubewarden.Code(400))
	}

	logger.DebugWithFields("validating pod object", func(e onelog.Entry) {
		e.String("name", pod.Metadata.Name)
		e.String("namespace", pod.Metadata.Namespace)
	})

	for label, value := range pod.Metadata.Labels {
		if err := validateLabel(label, value, &settings); err != nil {
			return kubewarden.RejectRequest(
				kubewarden.Message(err.Error()),
				kubewarden.NoCode)
		}
	}

	for requiredLabel := range settings.ConstrainedLabels {
		_, found := pod.Metadata.Labels[requiredLabel]
		if !found {
			return kubewarden.RejectRequest(
				kubewarden.Message(fmt.Sprintf(
					"constrained label %q not found inside of Pod",
					requiredLabel),
				),
				kubewarden.NoCode)
		}
	}

	return kubewarden.AcceptRequest()
}

func validateLabel(label, value string, settings *Settings) error {
	if settings.DeniedLabels.Contains(label) {
		return fmt.Errorf("label %q is on the deny list", label)
	}

	regExp, found := settings.ConstrainedLabels[label]
	if found && !regExp.Match([]byte(value)) {
		return fmt.Errorf("label %q does not pass user-defined constraint", label)
	}

	return nil
}
