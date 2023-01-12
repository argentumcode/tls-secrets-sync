package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func Test_KubernetesSyncer(t *testing.T) {
	checkSecret := func(tlsCert []byte, tlsKey []byte, checkAnnotation bool) func(t *testing.T, clientset kubernetes.Interface, err error) {
		return func(t *testing.T, clientset kubernetes.Interface, err error) {
			assert.Nil(t, err)
			sec, err := clientset.CoreV1().Secrets("test-namespace").Get(context.Background(), "sec-cert", metav1.GetOptions{})
			assert.Nil(t, err)
			if checkAnnotation {
				assert.Equal(t, "sec-cert", sec.Annotations[annotationKey])
			}
			assert.Equal(t, apiv1.SecretTypeTLS, sec.Type)
			assert.Equal(t, tlsCert, sec.Data["tls.crt"])
			assert.Equal(t, tlsKey, sec.Data["tls.key"])
		}
	}

	ctx := context.Background()
	testCases := []struct {
		Name       string
		Namespaces []apiv1.Namespace
		Secrets    []apiv1.Secret
		Check      func(t *testing.T, clientset kubernetes.Interface, err error)
	}{
		{
			Name: "DoNothingIfAnnotationMismathced",
			Namespaces: []apiv1.Namespace{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-namespace",
						Annotations: map[string]string{
							annotationKey: "not-sec-cert",
						},
					},
				},
			},
			Secrets: nil,
			Check: func(t *testing.T, clientset kubernetes.Interface, err error) {
				assert.Nil(t, err)
				list, err := clientset.CoreV1().Secrets("test-namespace").List(context.Background(), metav1.ListOptions{})
				assert.Nil(t, err)
				assert.Equal(t, 0, len(list.Items))
			},
		},
		{
			Name: "CreateNewSecretIfNotFound",
			Namespaces: []apiv1.Namespace{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-namespace",
						Annotations: map[string]string{
							annotationKey: "sec-cert",
						},
					},
				},
			},
			Check: checkSecret([]byte{61, 62, 63, 64}, []byte{65, 66, 67, 68}, true),
		},
		{
			Name: "UpdateSecretIfNotMatched",
			Namespaces: []apiv1.Namespace{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-namespace",
						Annotations: map[string]string{
							annotationKey: "sec-cert",
						},
					},
				},
			},
			Secrets: []apiv1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-cert",
						Namespace: "test-namespace",
						Annotations: map[string]string{
							annotationKey: "sec-cert",
						},
					},
					Type: apiv1.SecretTypeTLS,
					Data: map[string][]byte{
						"tls.crt": {64, 62, 63, 64},
						"tls.key": {69, 66, 67, 68},
					},
				},
			},
			Check: checkSecret([]byte{61, 62, 63, 64}, []byte{65, 66, 67, 68}, true),
		},
		{
			Name: "NotUpdateSecretIfAnnotationKeyMismathced",
			Namespaces: []apiv1.Namespace{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-namespace",
						Annotations: map[string]string{
							annotationKey: "sec-cert",
						},
					},
				},
			},
			Secrets: []apiv1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-cert",
						Namespace: "test-namespace",
						Annotations: map[string]string{
							annotationKey: "sec-cert2",
						},
					},
					Type: apiv1.SecretTypeTLS,
					Data: map[string][]byte{
						"tls.crt": {64, 62, 63, 64},
						"tls.key": {69, 66, 67, 68},
					},
				},
			},
			Check: checkSecret([]byte{64, 62, 63, 64}, []byte{69, 66, 67, 68}, false),
		},
		{
			Name: "RemoveSecretIfNamespaceAnnotationIsNotFound",
			Namespaces: []apiv1.Namespace{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-namespace",
						Annotations: map[string]string{
							annotationKey: "",
						},
					},
				},
			},
			Secrets: []apiv1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-cert",
						Namespace: "test-namespace",
						Annotations: map[string]string{
							annotationKey: "sec-cert",
						},
					},
					Type: apiv1.SecretTypeTLS,
					Data: map[string][]byte{
						"tls.crt": {64, 62, 63, 64},
						"tls.key": {69, 66, 67, 68},
					},
				},
			},
			Check: func(t *testing.T, clientset kubernetes.Interface, err error) {
				assert.Nil(t, err)
				list, err := clientset.CoreV1().Secrets("test-namespace").List(context.Background(), metav1.ListOptions{})
				assert.Nil(t, err)
				assert.Equal(t, 0, len(list.Items))
			},
		},
		{
			Name: "DoNotRemoveSecretIfAnnotationIsMismatched",
			Namespaces: []apiv1.Namespace{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-namespace",
						Annotations: map[string]string{
							annotationKey: "",
						},
					},
				},
			},
			Secrets: []apiv1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-cert",
						Namespace: "test-namespace",
						Annotations: map[string]string{
							annotationKey: "sec-cert2",
						},
					},
					Type: apiv1.SecretTypeTLS,
					Data: map[string][]byte{
						"tls.crt": {64, 62, 63, 64},
						"tls.key": {69, 66, 67, 68},
					},
				},
			},
			Check: checkSecret([]byte{64, 62, 63, 64}, []byte{69, 66, 67, 68}, false),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()
			for _, ns := range tc.Namespaces {
				if _, err := clientset.CoreV1().Namespaces().Create(ctx, &ns, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			for _, sc := range tc.Secrets {
				if _, err := clientset.CoreV1().Secrets(sc.ObjectMeta.Namespace).Create(ctx, &sc, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			syncer := NewKubernetesSyncer(clientset, "sec-cert")
			err := syncer.Sync(ctx, []byte{61, 62, 63, 64}, []byte{65, 66, 67, 68})
			tc.Check(t, clientset, err)
		})

	}
}

func Test_KubernetesFetcher(t *testing.T) {
	ctx := context.Background()
	clientset := fake.NewSimpleClientset()
	fetcher := NewKubernetesFetcher(clientset, "certs", "sec-cert")
	_, _, err := fetcher.Fetch(ctx)
	assert.True(t, errors.IsNotFound(err))

	if _, err := clientset.CoreV1().Secrets("certs").Create(ctx, &apiv1.Secret{
		Type: apiv1.SecretTypeTLS,
		ObjectMeta: metav1.ObjectMeta{
			Name: "sec-cert",
		},
		Data: map[string][]byte{
			"tls.crt": {61, 62, 63, 64},
			"tls.key": {65, 66, 67, 68},
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	cert, key, err := fetcher.Fetch(ctx)
	assert.Nil(t, err)
	assert.Equal(t, []byte{61, 62, 63, 64}, cert)
	assert.Equal(t, []byte{65, 66, 67, 68}, key)
}
