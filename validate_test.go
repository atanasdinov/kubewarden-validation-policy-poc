package main

import (
	"testing"

	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
	"github.com/mailru/easyjson"
)

func TestValidateLabel(t *testing.T) {
	tests := []struct {
		name              string
		podLabels         map[string]string
		deniedLabels      []string
		constrainedLabels map[string]string
		expectedIsValid   bool
	}{
		{
			name:              "pod without labels is accepted",
			podLabels:         make(map[string]string),
			deniedLabels:      []string{"owner"},
			constrainedLabels: make(map[string]string),
			expectedIsValid:   true,
		},
		{
			name: "pod without denied labels is accepted",
			podLabels: map[string]string{
				"hello": "world",
			},
			deniedLabels:      []string{"owner"},
			constrainedLabels: make(map[string]string),
			expectedIsValid:   true,
		},
		{
			name: "pod with a denied label is rejected",
			podLabels: map[string]string{
				"hello": "world",
			},
			deniedLabels:      []string{"hello"},
			constrainedLabels: make(map[string]string),
			expectedIsValid:   false,
		},
		{
			name: "pod with a satisfied constraint label is accepted",
			podLabels: map[string]string{
				"cc-center": "team-123",
			},
			deniedLabels: []string{"hello"},
			constrainedLabels: map[string]string{
				"cc-center": `team-\d+`,
			},
			expectedIsValid: true,
		},
		{
			name: "pod with an unsatisfied constraint label is rejected",
			podLabels: map[string]string{
				"cc-center": "team-kubewarden",
			},
			deniedLabels: []string{"hello"},
			constrainedLabels: map[string]string{
				"cc-center": `team-\d+`,
			},
			expectedIsValid: false,
		},
		{
			name: "pod missing a constrained label is rejected",
			podLabels: map[string]string{
				"owner": "team-kubewarden",
			},
			deniedLabels: []string{"hello"},
			constrainedLabels: map[string]string{
				"cc-center": `team-\d+`,
			},
			expectedIsValid: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			basicSettings := BasicSettings{
				DeniedLabels:      test.deniedLabels,
				ConstrainedLabels: test.constrainedLabels,
			}

			pod := corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Labels:    test.podLabels,
				},
			}

			payload, err := kubewarden_testing.BuildValidationRequest(&pod, &basicSettings)
			if err != nil {
				t.Errorf("Unexpected request error: %+v", err)
			}

			responsePayload, err := validate(payload)
			if err != nil {
				t.Errorf("Unexpected validation error: %+v", err)
			}

			var response kubewarden_protocol.ValidationResponse
			if err = easyjson.Unmarshal(responsePayload, &response); err != nil {
				t.Errorf("Unexpected response error: %+v", err)
			}

			if test.expectedIsValid && !response.Accepted {
				t.Errorf("Unexpected rejection: %s", *response.Message)
			}

			if !test.expectedIsValid && response.Accepted {
				t.Errorf("Unexpected acceptance")
			}
		})
	}
}
