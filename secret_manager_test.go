package main

import (
	"context"
	"net"
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/stretchr/testify/assert"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type fakeSecretManagerServer struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
	secretData map[string][]byte
}

func newFakeSecretManagerServer() *fakeSecretManagerServer {
	return &fakeSecretManagerServer{
		secretData: make(map[string][]byte),
	}
}

func (s *fakeSecretManagerServer) AccessSecretVersion(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	if data, ok := s.secretData[req.Name]; ok {
		return &secretmanagerpb.AccessSecretVersionResponse{
			Name:    req.Name,
			Payload: &secretmanagerpb.SecretPayload{Data: data},
		}, nil
	}
	return nil, status.Errorf(codes.NotFound, "Not Found")
}

func (s *fakeSecretManagerServer) AddSecretVersion(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	s.secretData[req.GetParent()+"/versions/latest"] = req.Payload.Data
	return &secretmanagerpb.SecretVersion{}, nil
}

func fakeServerForSecretManager(t *testing.T) (*secretmanager.Client, *fakeSecretManagerServer) {
	// Setup the fake server.
	fakeServer := newFakeSecretManagerServer()
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	gsrv := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(gsrv, fakeServer)
	fakeServerAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err == grpc.ErrServerStopped {
		} else if err != nil {
			panic(err)
		}
	}()
	t.Cleanup(gsrv.Stop)

	// Create a client.
	client, err := secretmanager.NewClient(context.Background(),
		option.WithEndpoint(fakeServerAddr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatal(err)
	}
	return client, fakeServer
}

func TestSecretManagerFetcher(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		Name         string
		Data         map[string][]byte
		Error        string
		ExpectedCert []byte
		ExpectedKey  []byte
	}{
		{
			Name: "Happy Path",
			Data: map[string][]byte{
				"projects/test-project/secrets/cert-secret/versions/latest": {61, 62, 63, 64},
				"projects/test-project/secrets/key-secret/versions/latest":  {65, 66, 67, 68},
			},
			Error:        "",
			ExpectedCert: []byte{61, 62, 63, 64},
			ExpectedKey:  []byte{65, 66, 67, 68},
		},
		{
			Name: "Cert Not Found",
			Data: map[string][]byte{
				"projects/test-project/secrets/key-secret/versions/latest": {65, 66, 67, 68},
			},
			Error: "rpc error:",
		},
		{
			Name: "Key Not Found",
			Data: map[string][]byte{
				"projects/test-project/secrets/cert-secret/versions/latest": {61, 62, 63, 64},
			},
			Error: "rpc error:",
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			// Create a client.
			client, fs := fakeServerForSecretManager(t)
			syncer := NewSecretManagerFetcher(client, "test-project", "cert-secret", "key-secret")
			fs.secretData = tc.Data
			if tlsCert, tlsKey, err := syncer.Fetch(ctx); err != nil {
				if tc.Error == "" {
					t.Errorf("unexpected error in sync: %+v", err)
				} else {
					assert.Contains(t, err.Error(), tc.Error)
				}
			} else {
				if tc.Error != "" {
					t.Errorf("unexpected sucess in sync expected: %+v", tc.Error)
				} else {
					assert.Equal(t, tc.ExpectedCert, tlsCert)
					assert.Equal(t, tc.ExpectedKey, tlsKey)
				}
			}
		})
	}
}

func TestSecretManagerSyncer(t *testing.T) {
	ctx := context.Background()
	// Create a client.
	client, _ := fakeServerForSecretManager(t)
	syncer := NewSecretManagerSyncer(client, "test-project", "cert-secret", "key-secret")
	if err := syncer.Sync(ctx, []byte("tlsCert"), []byte("tlsKey")); err != nil {
		t.Errorf("unexpected error in sync: %+v", err)
	}
}
