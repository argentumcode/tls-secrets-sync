package main

import (
	"bytes"
	"context"
	"log"
	"strings"

	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

type KubernetesSyncer struct {
	k          kubernetes.Interface
	secretName string
}

func NewKubernetesSyncer(k kubernetes.Interface, secretName string) *KubernetesSyncer {
	return &KubernetesSyncer{
		k:          k,
		secretName: secretName,
	}
}

func (s *KubernetesSyncer) checkAnnotations(list string, key string) bool {
	for _, k := range strings.Split(list, ",") {
		if k == key {
			return true
		}
	}
	return false
}

func (s *KubernetesSyncer) Sync(ctx context.Context, tlsCert []byte, tlsKey []byte) error {
	namespaces, err := s.k.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, ns := range namespaces.Items {
		createSecret := s.checkAnnotations(ns.GetAnnotations()[annotationKey], s.secretName)

		secret, err := s.k.CoreV1().Secrets(ns.Name).Get(ctx, s.secretName, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			if createSecret {
				log.Printf("create secret for namespace=%s,name=%s", ns.Name, s.secretName)
				secret := apiv1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: s.secretName,
						Annotations: map[string]string{
							annotationKey: s.secretName,
						},
					},
					Type: apiv1.SecretTypeTLS,
					Data: map[string][]byte{
						"tls.key": tlsKey,
						"tls.crt": tlsCert,
					},
				}
				_, err := s.k.CoreV1().Secrets(ns.Name).Create(ctx, &secret, metav1.CreateOptions{})
				if err != nil {
					return err
				}
			}
		} else if err != nil {
			return err

		} else {
			if secret.GetAnnotations()[annotationKey] != s.secretName {
				continue
			}
			if createSecret {
				// Sync
				if bytes.Compare(secret.Data["tls.key"], tlsKey) != 0 || bytes.Compare(secret.Data["tls.crt"], tlsCert) != 0 {
					// Update Secret
					log.Printf("update secret for namespace=%s,name=%s", ns.Name, s.secretName)
					secret.Data["tls.key"] = tlsKey
					secret.Data["tls.crt"] = tlsCert
					_, err := s.k.CoreV1().Secrets(ns.Name).Update(ctx, secret, metav1.UpdateOptions{})
					if err != nil {
						return err
					}
				}
			} else {
				log.Printf("remove secret for namespace=%s,name=%s", ns.Name, s.secretName)
				if err := s.k.CoreV1().Secrets(ns.Name).Delete(ctx, secret.Name, metav1.DeleteOptions{}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type KubernetesFetcher struct {
	k          kubernetes.Interface
	namespace  string
	secretName string
}

func NewKubernetesFetcher(k kubernetes.Interface, namespace string, secretName string) *KubernetesFetcher {
	return &KubernetesFetcher{
		k:          k,
		namespace:  namespace,
		secretName: secretName,
	}
}

func (f *KubernetesFetcher) Fetch(ctx context.Context) ([]byte, []byte, error) {
	ret, err := f.k.CoreV1().Secrets(f.namespace).Get(ctx, f.secretName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	return ret.Data["tls.crt"], ret.Data["tls.key"], nil
}
