/*
Copyright (C) 2022-2024 ApeCloud Co., Ltd

This file is part of KubeBlocks project

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"

	appsv1alpha1 "github.com/apecloud/kubeblocks/apis/apps/v1alpha1"
	"github.com/apecloud/kubeblocks/pkg/constant"

	"github.com/apecloud/kbcli/pkg/types"
)

const (
	passwordRestartTimeout       = 10 * time.Minute
	passwordRestartPollInterval  = time.Second
	passwordSecretReadyTimeout   = 30 * time.Second
	passwordSecretReadyPollRatio = 20
)

func (o *ChangePasswordOptions) restartComponentAfterPasswordChange(ctx context.Context, immutableSecrets []*corev1.Secret) error {
	if o.Dynamic == nil {
		return errors.New("the restart option requires a Kubernetes dynamic client")
	}
	if err := o.waitForRecreatedPasswordSecrets(ctx, immutableSecrets); err != nil {
		return err
	}

	opsRequest := passwordRestartOpsRequest(o.Namespace, o.ClusterName, o.ComponentName)
	created, err := createPasswordRestartOpsRequest(ctx, o.Dynamic, opsRequest)
	if err != nil {
		return err
	}
	if err = waitForPasswordRestart(ctx, o.Dynamic, o.Namespace, created.Name,
		passwordRestartTimeout, passwordRestartPollInterval); err != nil {
		return err
	}
	fmt.Fprintf(o.Out, "Component %s/%s restarted successfully with OpsRequest %s.\n",
		o.ClusterName, o.ComponentName, created.Name)
	return nil
}

func passwordRestartOpsRequest(namespace, cluster, component string) *appsv1alpha1.OpsRequest {
	return &appsv1alpha1.OpsRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: appsv1alpha1.APIVersion,
			Kind:       "OpsRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      fmt.Sprintf("kbcli-password-restart-%d", time.Now().UnixNano()),
			Labels: map[string]string{
				"app.kubernetes.io/instance":   cluster,
				"app.kubernetes.io/managed-by": "kbcli",
			},
		},
		Spec: appsv1alpha1.OpsRequestSpec{
			ClusterName: cluster,
			Type:        appsv1alpha1.RestartType,
			SpecificOpsRequest: appsv1alpha1.SpecificOpsRequest{
				RestartList: []appsv1alpha1.ComponentOps{{ComponentName: component}},
			},
		},
	}
}

func createPasswordRestartOpsRequest(ctx context.Context, client dynamic.Interface, opsRequest *appsv1alpha1.OpsRequest) (*appsv1alpha1.OpsRequest, error) {
	data, err := json.Marshal(opsRequest)
	if err != nil {
		return nil, fmt.Errorf("marshal restart OpsRequest: %w", err)
	}
	object := &unstructured.Unstructured{}
	if err = json.Unmarshal(data, object); err != nil {
		return nil, fmt.Errorf("convert restart OpsRequest: %w", err)
	}

	created, err := client.Resource(types.OpsGVR()).Namespace(opsRequest.Namespace).Create(ctx, object, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create restart OpsRequest %s/%s: %w", opsRequest.Namespace, opsRequest.Name, err)
	}
	return opsRequestFromUnstructured(created)
}

func waitForPasswordRestart(ctx context.Context, client dynamic.Interface, namespace, name string, timeout, interval time.Duration) error {
	err := wait.PollUntilContextTimeout(ctx, interval, timeout, true, func(ctx context.Context) (bool, error) {
		object, err := client.Resource(types.OpsGVR()).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		opsRequest, err := opsRequestFromUnstructured(object)
		if err != nil {
			return false, err
		}
		switch opsRequest.Status.Phase {
		case appsv1alpha1.OpsSucceedPhase:
			return true, nil
		case appsv1alpha1.OpsFailedPhase, appsv1alpha1.OpsCancelledPhase, appsv1alpha1.OpsAbortedPhase:
			message := passwordRestartFailureMessage(opsRequest)
			return false, fmt.Errorf("restart OpsRequest %s/%s finished with phase %s: %s", namespace, name, opsRequest.Status.Phase, message)
		default:
			return false, nil
		}
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, wait.ErrWaitTimeout) {
		return fmt.Errorf("timed out waiting for restart OpsRequest %s/%s to succeed", namespace, name)
	}
	return fmt.Errorf("wait for restart OpsRequest %s/%s: %w", namespace, name, err)
}

func (o *ChangePasswordOptions) waitForRecreatedPasswordSecrets(ctx context.Context, secrets []*corev1.Secret) error {
	if len(secrets) == 0 {
		return nil
	}
	timeout := passwordSecretReadyTimeout
	if o.AccountRootSecretWaitTimeout > timeout {
		timeout = o.AccountRootSecretWaitTimeout
	}
	return wait.PollUntilContextTimeout(ctx, timeout/time.Duration(passwordSecretReadyPollRatio), timeout, true, func(ctx context.Context) (bool, error) {
		for _, oldSecret := range secrets {
			if oldSecret == nil {
				continue
			}
			secret, err := o.kube().CoreV1().Secrets(o.Namespace).Get(ctx, oldSecret.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			if secret.DeletionTimestamp != nil || string(secret.Data[constant.AccountPasswdForSecret]) != o.Password {
				return false, nil
			}
		}
		return true, nil
	})
}

func opsRequestFromUnstructured(object *unstructured.Unstructured) (*appsv1alpha1.OpsRequest, error) {
	opsRequest := &appsv1alpha1.OpsRequest{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, opsRequest); err != nil {
		return nil, fmt.Errorf("convert restart OpsRequest %s/%s: %w", object.GetNamespace(), object.GetName(), err)
	}
	if opsRequest.Name == "" {
		opsRequest.Name = object.GetName()
	}
	opsRequest.Namespace = object.GetNamespace()
	return opsRequest, nil
}

func passwordRestartFailureMessage(opsRequest *appsv1alpha1.OpsRequest) string {
	for i := range opsRequest.Status.Conditions {
		condition := opsRequest.Status.Conditions[i]
		if condition.Status != metav1.ConditionFalse {
			continue
		}
		message := strings.TrimSpace(condition.Message)
		if message != "" {
			return message
		}
	}
	return "no failure message was reported"
}
