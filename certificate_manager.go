package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"

	certificatemanager "cloud.google.com/go/certificatemanager/apiv1"
	"cloud.google.com/go/certificatemanager/apiv1/certificatemanagerpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

type CertificateManagerSyncer struct {
	client                  *certificatemanager.Client
	projectId               string
	location                string
	certificateNamePrefix   string
	certificateMapName      string
	certificateMapEntryName string
	hostName                string
}

func NewCertificateManagerSyncer(client *certificatemanager.Client, hostName string, projectId string, location string, certificateNamePrefix string, certificateMapName string, certificateMapEntryName string) Syncer {
	return &CertificateManagerSyncer{
		client:                  client,
		hostName:                hostName,
		projectId:               projectId,
		location:                location,
		certificateNamePrefix:   certificateNamePrefix,
		certificateMapName:      certificateMapName,
		certificateMapEntryName: certificateMapEntryName,
	}
}

func (c *CertificateManagerSyncer) Sync(ctx context.Context, tlsCert []byte, tlsKey []byte) error {
	certificateNameHash := sha256.Sum256(tlsCert)
	certificateName := fmt.Sprintf("%s%x", c.certificateNamePrefix, certificateNameHash[:4])
	certificateFullName := fmt.Sprintf("projects/%s/locations/%s/certificates/%s", c.projectId, c.location, certificateName)

	_, err := c.client.GetCertificate(ctx, &certificatemanagerpb.GetCertificateRequest{
		Name: certificateFullName,
	})
	createNewCertificate := false
	if err != nil && status.Code(err) == codes.NotFound {
		createNewCertificate = true
	} else if err != nil {
		return fmt.Errorf("get certificate: %w", err)
	}
	if createNewCertificate {
		log.Printf("Start creating certificate \"%s\"", certificateName)
		op, err := c.client.CreateCertificate(ctx, &certificatemanagerpb.CreateCertificateRequest{
			Parent:        fmt.Sprintf("projects/%s/locations/%s", c.projectId, c.location),
			CertificateId: certificateName,
			Certificate: &certificatemanagerpb.Certificate{
				Name: certificateName,
				Labels: map[string]string{
					"managed-by": "tls-secrets-sync",
				},
				Type: &certificatemanagerpb.Certificate_SelfManaged{
					SelfManaged: &certificatemanagerpb.Certificate_SelfManagedCertificate{
						PemCertificate: string(tlsCert),
						PemPrivateKey:  string(tlsKey),
					},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("create certificate: %w", err)
		}
		_, err = op.Wait(ctx)
		if err != nil {
			return fmt.Errorf("wait for certificate creation: %w", err)
		}
		log.Printf("Complete creating certificate \"%s\"", certificateName)
	}
	// Attach to certificate map entry
	mapEntry, err := c.client.GetCertificateMapEntry(ctx, &certificatemanagerpb.GetCertificateMapEntryRequest{
		Name: fmt.Sprintf("projects/%s/locations/%s/certificateMaps/%s/certificateMapEntries/%s", c.projectId, c.location, c.certificateMapName, c.certificateMapEntryName),
	})
	createNewMapEntry := false
	if err != nil && status.Code(err) == codes.NotFound {
		createNewMapEntry = true
	} else if err != nil {
		return fmt.Errorf("get certificate map entry: %w", err)
	}
	if createNewMapEntry {
		log.Printf("Start creating certificate map entry \"%s\"", c.certificateMapEntryName)
		op, err := c.client.CreateCertificateMapEntry(ctx, &certificatemanagerpb.CreateCertificateMapEntryRequest{
			Parent:                fmt.Sprintf("projects/%s/locations/%s/certificateMaps/%s", c.projectId, c.location, c.certificateMapName),
			CertificateMapEntryId: c.certificateMapEntryName,
			CertificateMapEntry: &certificatemanagerpb.CertificateMapEntry{
				Name: c.certificateMapEntryName,
				Labels: map[string]string{
					"managed-by": "tls-secrets-sync",
				},
				Certificates: []string{certificateFullName},
				Match: &certificatemanagerpb.CertificateMapEntry_Hostname{
					Hostname: c.hostName,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("create certificate map entry: %w", err)
		}
		_, err = op.Wait(ctx)
		if err != nil {
			return fmt.Errorf("wait for certificate map creation: %w", err)
		}
		log.Printf("Complete creating certificate map entry \"%s\"", c.certificateMapEntryName)
	} else {
		updateCertificate := true
		var removeCertificates []string
		if len(mapEntry.Certificates) != 1 || mapEntry.Certificates[0] != certificateFullName {
			updateCertificate = true
			removeCertificates = mapEntry.Certificates
			mapEntry.Certificates = []string{certificateFullName}
		}
		if updateCertificate {
			log.Printf("Start updating certificate map entry \"%s\"", c.certificateMapEntryName)
			op, err := c.client.UpdateCertificateMapEntry(ctx, &certificatemanagerpb.UpdateCertificateMapEntryRequest{
				CertificateMapEntry: mapEntry,
				UpdateMask: &fieldmaskpb.FieldMask{
					Paths: []string{"certificates"},
				},
			})
			if err != nil {
				return fmt.Errorf("update certificate map entry: %w", err)
			}
			_, err = op.Wait(ctx)
			if err != nil {
				return fmt.Errorf("wait for certificate map entry update: %w", err)
			}
			log.Printf("Complete updating certificate map entry \"%s\"", c.certificateMapEntryName)
		}

		for _, certificate := range removeCertificates {
			log.Printf("Start deleting certificate \"%s\"", certificate)
			op, err := c.client.DeleteCertificate(ctx, &certificatemanagerpb.DeleteCertificateRequest{
				Name: certificate,
			})
			if err != nil {
				return fmt.Errorf("delete certificate: %w", err)
			}
			err = op.Wait(ctx)
			if err != nil {
				return fmt.Errorf("wait for certificate deletion: %w", err)
			}
			log.Printf("Complete deleting certificate \"%s\"", certificate)
		}
	}
	return nil
}
