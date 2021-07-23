/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/pkg/errors"
	"io"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/util/keyutil"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	certmanageriov1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	errors2 "github.com/mgazza/cert-backup/errors"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	certUtil "k8s.io/client-go/util/cert"
)

// CertificateReconciler reconciles a Certificate object
type CertificateReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	Storage Storage
}

type Storage interface {
	Upload(name string, body io.Reader) error
	Download(name string, w io.WriterAt) error
}

//+kubebuilder:rbac:groups=cert-manager.io.my.domain,resources=certificates,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cert-manager.io.my.domain,resources=certificates/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cert-manager.io.my.domain,resources=certificates/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Certificate object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	cert := &certmanageriov1.Certificate{}
	// your logic here
	err := r.Get(ctx, req.NamespacedName, cert)
	if err != nil {
		// if we can't load the cert then we need to stop processing it
		return ctrl.Result{}, err
	}

	secret := &v1.Secret{}
	secretFullName := types.NamespacedName{
		Namespace: req.NamespacedName.Namespace,
		Name:      cert.Spec.SecretName,
	}
	err = r.Get(ctx, secretFullName, secret)
	if err != nil && !k8serrors.IsNotFound(err) {
		return ctrl.Result{Requeue: true}, errors.Wrap(err, fmt.Sprintf("error getting secret %s", secretFullName))
	}

	fileName := fmt.Sprintf("%s:%s.json", secretFullName.Namespace, secretFullName.Name)
	secretValid, err := verifySecret(secret)
	if err != nil {
		// some unknown error verifying the secret continue
		logger.Error(err, "error verifying secret", "secret", secretFullName)
	}

	if secretValid {
		// update the Storage one
		b, err := json.Marshal(secret)
		if err != nil {
			// retry
			return ctrl.Result{Requeue: true}, errors.Wrap(err, fmt.Sprintf("unable to marshal secret %s to json", secretFullName))
		}
		err = r.Storage.Upload(fileName, bytes.NewBuffer(b))
		if err != nil {
			// retry
			return ctrl.Result{Requeue: true}, errors.Wrap(err, "error uploading secret to storage")
		}
		// were done now
		return ctrl.Result{}, nil
	}

	// the (existing?) secret isn't valid

	// download the Storage secret
	buff := aws.NewWriteAtBuffer([]byte{})
	err = r.Storage.Download(fileName, buff)
	if err != nil {
		// if it doesnt exist do nothing
		if errors.Is(err, errors2.ErrNotFound) {
			return ctrl.Result{}, nil
		}

		// if we get some temporary issue retry
		return ctrl.Result{Requeue: true}, errors.Wrap(err, "error downloading secret from storage")
	}

	// unmarshal the download as a secret
	storageSecret := &v1.Secret{}
	err = json.Unmarshal(buff.Bytes(), storageSecret)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, fmt.Sprintf("unable to unmarshal secret %s from json", secretFullName))
	}
	storageSecretValid, err := verifySecret(storageSecret)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, fmt.Sprintf("backed up secret %s is not valid", secretFullName))
	}
	if storageSecretValid {
		// clear out the resource version
		storageSecret.ResourceVersion = ""
		// restore the secret
		err := r.Create(ctx, storageSecret)
		if err != nil {
			// retry
			return ctrl.Result{Requeue: true}, errors.Wrap(err, fmt.Sprintf("error restoring secret %s", secretFullName))
		}
		return ctrl.Result{}, nil
	}

	// shouldn't get here
	return ctrl.Result{}, errors.Wrap(err, fmt.Sprintf("backed up secret %s is not valid", secretFullName))
}

var (
	// ErrPrivateKeyNotRSA is returned when the private key is not a valid RSA key.
	ErrPrivateKeyNotRSA = errors.New("private key is not an RSA key")
)

var now = func() time.Time {
	return time.Now()
}

func verifySecret(secret *v1.Secret) (bool, error) {
	_, certs, err := readKey(secret)
	if err != nil {
		return false, err
	}
	n := now()
	for _, cert := range certs {
		for _, name := range cert.DNSNames {
			err := cert.VerifyHostname(name)
			if err != nil {
				return false, nil
			}
		}
		if n.Before(cert.NotBefore) || n.After(cert.NotAfter) {
			return false, nil
		}
	}
	return true, nil
}

func readKey(secret *v1.Secret) (*rsa.PrivateKey, []*x509.Certificate, error) {
	key, err := keyutil.ParsePrivateKeyPEM(secret.Data[v1.TLSPrivateKeyKey])
	if err != nil {
		return nil, nil, err
	}
	switch rsaKey := key.(type) {
	case *rsa.PrivateKey:
		certs, err := certUtil.ParseCertsPEM(secret.Data[v1.TLSCertKey])
		if err != nil {
			return nil, nil, err
		}
		return rsaKey, certs, nil
	default:
		return nil, nil, ErrPrivateKeyNotRSA
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certmanageriov1.Certificate{}).
		Complete(r)
}
