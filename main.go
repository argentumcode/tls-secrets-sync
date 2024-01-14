package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	certificatemanager "cloud.google.com/go/certificatemanager/apiv1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/clientcmd"
)

const annotationKey = "tls-secrets-sync.argentumcode.co.jp"

type Syncer interface {
	Sync(ctx context.Context, tlsCert []byte, tlsKey []byte) error
}

type Fetcher interface {
	Fetch(ctx context.Context) ([]byte, []byte, error)
}

var clientset kubernetes.Interface
var secretManagerClient *secretmanager.Client
var version string
var (
	errorCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tls_secret_sync_error_count",
		Help: "The error count",
	})
	successCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tls_secret_sync_success_count",
		Help: "The successfully sync count",
	})
)

func getKubernetesClient() (kubernetes.Interface, error) {
	if clientset == nil {
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()

		configOverrides := &clientcmd.ConfigOverrides{}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
		clientConfig, err := kubeConfig.ClientConfig()
		if err != nil {
			return nil, err
		}
		client, err := kubernetes.NewForConfig(clientConfig)
		if err != nil {
			return nil, err
		}
		clientset = client
	}
	return clientset, nil
}

func getSecretManagerClient(ctx context.Context) (*secretmanager.Client, error) {
	if secretManagerClient == nil {
		c, err := secretmanager.NewClient(ctx)
		if err != nil {
			return nil, err
		}
		secretManagerClient = c
	}
	return secretManagerClient, nil
}

func rootCmd() *cobra.Command {
	var sourceType string
	var sourceNamespace string
	var secretName string
	var secretManagerProject string
	var secretManagerTlsCertName string
	var secretManagerTlsKeyName string
	var certificateManagerHostName string
	var certificateManagerProject string
	var certificateManagerLocation string
	var certificateManagerCertificateNamePrefix string
	var certificateManagerCertificateMap string
	var certificateManagerCertificateMapEntry string
	var metricsListen string
	var syncTypes []string
	rootCmd := &cobra.Command{
		Use:           "tls-secret-sync",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var source Fetcher
			ctx := cmd.Context()
			if sourceType == "kubernetes" {
				if sourceNamespace == "" {
					return errors.New("source-namespace is required if source-type is kubernetes")
				}
				if secretName == "" {
					return errors.New("secret-name is required if source-type is kubernetes")
				}
				c, err := getKubernetesClient()
				if err != nil {
					return errors.Wrap(err, "failed to create kubernetes client")
				}
				source = NewKubernetesFetcher(c, sourceNamespace, secretName)
			} else if sourceType == "secret-manager" {
				if secretManagerProject == "" {
					return errors.New("secret-manager-gcp-project is required if source / sync type has secret-manager")
				}
				if secretManagerTlsCertName == "" {
					return errors.New("cert-secret is required if source / sync type has secret-manager")
				}
				if secretManagerTlsKeyName == "" {
					return errors.New("key-secret is required if source / sync type has secret-manager")
				}
				c, err := getSecretManagerClient(ctx)
				if err != nil {
					return errors.Wrap(err, "failed to create secret-manager client")
				}
				source = NewSecretManagerFetcher(c, secretManagerProject, secretManagerTlsCertName, secretManagerTlsKeyName)
			} else {
				return fmt.Errorf("invalid value for source-type: %s", sourceType)
			}
			syncer := make([]Syncer, 0)
			for _, s := range syncTypes {
				if s == "kubernetes" {
					if secretName == "" {
						return errors.New("secret-name is required if source-type is kubernetes")
					}
					c, err := getKubernetesClient()
					if err != nil {
						return errors.Wrap(err, "failed to create kubernetes client")
					}
					syncer = append(syncer, NewKubernetesSyncer(c, secretName))
				} else if s == "secret-manager" {
					if secretManagerProject == "" {
						return errors.New("secret-manager-gcp-project is required if source / sync type has secret-manager")
					}
					if secretManagerTlsCertName == "" {
						return errors.New("cert-secret is required if source / sync type has secret-manager")
					}
					if secretManagerTlsKeyName == "" {
						return errors.New("key-secret is required if source / sync type has secret-manager")
					}
					c, err := getSecretManagerClient(ctx)
					if err != nil {
						return errors.Wrap(err, "failed to create secret-manager client")
					}
					syncer = append(syncer, NewSecretManagerSyncer(c, secretManagerProject, secretManagerTlsCertName, secretManagerTlsKeyName))
				} else if s == "certificate-manager" {
					if certificateManagerHostName == "" {
						return errors.New("certificate-manager-host-name is required if sync type has certificate-manager")
					}
					if certificateManagerProject == "" {
						return errors.New("certificate-manager-gcp-project is required if sync type has certificate-manager")
					}
					if certificateManagerCertificateNamePrefix == "" {
						return errors.New("certificate-manager-name-prefix is required if sync type has certificate-manager")
					}
					if certificateManagerCertificateMap == "" {
						return errors.New("certificate-manager-certificate-map is required if sync type has certificate-manager")
					}
					if certificateManagerCertificateMapEntry == "" {
						return errors.New("certificate-manager-certificate-map-entry is required if sync type has certificate-manager")
					}
					c, err := certificatemanager.NewClient(ctx)
					if err != nil {
						return errors.Wrap(err, "failed to create certificate-manager client")
					}
					syncer = append(syncer,
						NewCertificateManagerSyncer(c,
							certificateManagerHostName,
							certificateManagerProject,
							certificateManagerLocation,
							certificateManagerCertificateNamePrefix,
							certificateManagerCertificateMap,
							certificateManagerCertificateMapEntry,
						),
					)
				} else {
					return fmt.Errorf("invalid value for sync-type: %s", s)
				}
			}
			t := time.NewTicker(60 * time.Minute)
			errorCount.Add(0)
			successCount.Add(0)
			srv := &http.Server{Addr: metricsListen}
			http.Handle("/metrics", promhttp.Handler())
			go func() {
				if err := srv.ListenAndServe(); err == http.ErrServerClosed {
					log.Print("Server closed")
				} else if err != nil {
					log.Fatal("failed to listen metrics server", err)
				}
			}()
			defer func() {
				_ = srv.Shutdown(ctx)
			}()

		L:
			for {
				log.Print("Start Sync")
				tlsCert, tlsKey, err := source.Fetch(ctx)
				succses := true
				if err != nil {
					log.Print("failed to get secret: ", err)
					succses = false
				} else {
					for _, s := range syncer {
						err := s.Sync(ctx, tlsCert, tlsKey)
						if err != nil {
							log.Print("failed to sync secret: ", err)
							succses = false
						}
					}
				}
				if succses {
					log.Print("Success")
					successCount.Inc()
				} else {
					log.Print("Failed")
					errorCount.Inc()
				}
				select {
				case <-ctx.Done():
					break L
				case <-t.C:
				}
			}
			return nil
		},
	}
	rootCmd.Flags().StringVar(&sourceType, "source-type", "", "kubernetes/secret-manager")
	rootCmd.Flags().StringVar(&sourceNamespace, "source-namespace", "", "namespace to get tls secret")
	rootCmd.Flags().StringVar(&secretName, "secret-name", "", "secret name to sync")
	rootCmd.Flags().StringVar(&secretManagerProject, "secret-manager-gcp-project", "", "gcp project for secret-manager")
	rootCmd.Flags().StringVar(&secretManagerTlsCertName, "cert-secret", "", "cert secret name for secret-manager")
	rootCmd.Flags().StringVar(&secretManagerTlsKeyName, "key-secret", "", "key secret name for secret-namager")
	rootCmd.Flags().StringArrayVar(&syncTypes, "sync-types", nil, "kubernetes/secret-manager/certificate-manager")
	rootCmd.Flags().StringVar(&certificateManagerHostName, "certificate-manager-host-name", "", "host name for certifiacate-manager. ex: *.example.com")
	rootCmd.Flags().StringVar(&certificateManagerProject, "certificate-manager-gcp-project", "", "gcp project for certifiacate-manager")
	rootCmd.Flags().StringVar(&certificateManagerLocation, "certificate-manager-location", "global", "location for certifiacate-manager")
	rootCmd.Flags().StringVar(&certificateManagerCertificateNamePrefix, "certificate-manager-name-prefix", "", "certificate name prefix for certifiacate-manager")
	rootCmd.Flags().StringVar(&certificateManagerCertificateMap, "certificate-manager-certificate-map", "", "certificate map name for certifiacate-manager")
	rootCmd.Flags().StringVar(&certificateManagerCertificateMapEntry, "certificate-manager-certificate-map-entry", "", "certificate map entry name for certifiacate-manager")
	rootCmd.Flags().StringVar(&metricsListen, "metrics-listen", ":9090", "listen address:port for metrics-server")

	if err := rootCmd.MarkFlagRequired("source-type"); err != nil {
		panic(err)
	}

	return rootCmd
}

func main() {
	cmd := rootCmd()
	if err := rootCmd().Execute(); err != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%+v\n", err)
		os.Exit(1)
	}
}
