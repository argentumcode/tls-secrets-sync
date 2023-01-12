package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"
)

func prepareFake(t *testing.T) *fakeSecretManagerServer {
	s, f := fakeServerForSecretManager(t)
	secretManagerClient = s

	clientset = fake.NewSimpleClientset()
	return f
}

func TestRootCmd(t *testing.T) {
	validSourceK8sArgs := []string{"--source-type", "kubernetes", "--source-namespace", "certs", "--secret-name", "piyo"}
	validSourceSecretManagerArgs := []string{"--source-type", "secret-manager", "--gcp-project", "test-project", "--cert-secret", "cert-secret", "--key-secret", "key-secret"}
	testCases := []struct {
		Name          string
		Args          []string
		ExpectedError string
	}{
		{
			Name:          "No Argument",
			ExpectedError: "source-type\" not set",
		},
		{
			Name:          "Invalid Source Type",
			Args:          []string{"--source-type", "hogehoge"},
			ExpectedError: "hogehoge",
		},
		{
			Name:          "No Kubernetes Namespace Argument",
			Args:          []string{"--source-type", "kubernetes", "--secret-name", "tls-cert"},
			ExpectedError: "source-namespace is required",
		},
		{
			Name:          "No Kubernetes Secret Name Argument",
			Args:          []string{"--source-type", "kubernetes", "--source-namespace", "certs"},
			ExpectedError: "secret-name is required",
		},
		{
			Name:          "No Gcp Project Argument",
			Args:          []string{"--source-type", "secret-manager", "--cert-secret", "cert-secret", "--key-secret", "key-secret"},
			ExpectedError: "gcp-project is required",
		},
		{
			Name:          "No Cert Secret Argument",
			Args:          []string{"--source-type", "secret-manager", "--gcp-project", "test-project", "--key-secret", "key-secret"},
			ExpectedError: "cert-secret is required",
		},
		{
			Name:          "No Key Secret Argument",
			Args:          []string{"--source-type", "secret-manager", "--gcp-project", "test-project", "--cert-secret", "cert-secret"},
			ExpectedError: "key-secret is required",
		},
		{
			Name:          "Secret Manager Sync No Gcp Project",
			Args:          append(validSourceK8sArgs, "--sync-types", "secret-manager", "--cert-secret", "cert-secret", "--key-secret", "key-secret"),
			ExpectedError: "gcp-project is required",
		},
		{
			Name:          "Secret Manager Sync No Cert Secret",
			Args:          append(validSourceK8sArgs, "--sync-types", "secret-manager", "--gcp-project", "test-project", "--key-secret", "key-secret"),
			ExpectedError: "cert-secret is required",
		},
		{
			Name:          "Secret Manager Sync No Key Secret",
			Args:          append(validSourceK8sArgs, "--sync-types", "secret-manager", "--gcp-project", "test-project", "--cert-secret", "cert-secret"),
			ExpectedError: "key-secret is required",
		},
		{
			Name:          "Kubernetes Sync No SecretName",
			Args:          append(validSourceSecretManagerArgs, "--sync-types", "kubernetes"),
			ExpectedError: "secret-name is required",
		},
		{
			Name:          "Invalid Sync Name",
			Args:          append(validSourceSecretManagerArgs, "--sync-types", "hoge"),
			ExpectedError: "hoge",
		},
		{
			Name:          "Happy Case",
			Args:          append(validSourceK8sArgs, "--sync-types", "kubernetes"),
			ExpectedError: "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			prepareFake(t)
			cmd := rootCmd()
			cmd.SetArgs(tc.Args)
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			err := cmd.ExecuteContext(ctx)
			if tc.ExpectedError != "" {
				if err == nil {
					t.Errorf("Unexpected success")
				} else {
					assert.Contains(t, err.Error(), tc.ExpectedError)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %+v", err)
				}
			}
		})
	}
}
