package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SecretManagerFetcher struct {
	k         *secretmanager.Client
	certName  string
	keyName   string
	projectId string
}

func NewSecretManagerFetcher(client *secretmanager.Client, projectId string, certName string, keyName string) *SecretManagerFetcher {
	return &SecretManagerFetcher{
		k:         client,
		certName:  certName,
		keyName:   keyName,
		projectId: projectId,
	}
}
func (f *SecretManagerFetcher) Fetch(ctx context.Context) ([]byte, []byte, error) {
	cv, err := f.k.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", f.projectId, f.certName),
	})
	if err != nil {
		return nil, nil, err
	}
	kv, err := f.k.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", f.projectId, f.keyName),
	})
	if err != nil {
		return nil, nil, err
	}
	return cv.Payload.Data, kv.Payload.Data, nil
}

type SecretManagerSyncer struct {
	k         *secretmanager.Client
	certName  string
	keyName   string
	projectId string
}

func NewSecretManagerSyncer(client *secretmanager.Client, projectId string, certName string, keyName string) *SecretManagerSyncer {
	return &SecretManagerSyncer{
		k:         client,
		certName:  certName,
		keyName:   keyName,
		projectId: projectId,
	}
}

func (s *SecretManagerSyncer) reconcileSecret(ctx context.Context, secretName string, data []byte) error {
	v, err := s.k.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", s.projectId, secretName),
	})
	createNewVersion := false
	if err != nil && status.Code(err) == codes.NotFound {
		createNewVersion = true
	} else if err != nil {
		return err
	}
	if createNewVersion || !bytes.Equal(v.Payload.Data, data) {
		log.Printf("add secret version to %s", secretName)
		_, err := s.k.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
			Parent: fmt.Sprintf("projects/%s/secrets/%s", s.projectId, secretName),
			Payload: &secretmanagerpb.SecretPayload{
				Data: data,
			},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SecretManagerSyncer) Sync(ctx context.Context, tlsCert []byte, tlsKey []byte) error {
	if err := s.reconcileSecret(ctx, s.certName, tlsCert); err != nil {
		return err
	}
	if err := s.reconcileSecret(ctx, s.keyName, tlsKey); err != nil {
		return err
	}

	return nil
}
