/*
Copyright (C) 2022-2024 ApeCloud Co., Ltd

This file is part of KubeBlocks project

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package accounts

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/pointer"

	"github.com/apecloud/kubeblocks/pkg/constant"
)

const (
	passwordJobTimeout          = 2 * time.Minute
	passwordJobPollInterval     = 500 * time.Millisecond
	passwordJobContainerName    = "change-password"
	passwordJobScriptVolumeName = "password-script"
	passwordJobScriptMountPath  = "/change-password"
	passwordJobScriptKey        = "script"
)

type passwordJobSpec struct {
	command    []string
	env        []corev1.EnvVar
	script     []byte
	scriptName string
	secretData map[string][]byte
	secretEnv  []passwordJobSecretEnv
}

type passwordJobSecretEnv struct {
	name string
	key  string
}

// runPasswordJob executes a database client in a short-lived Job. Sensitive
// inputs are kept in a temporary Secret instead of the Job object, and are
// deleted as soon as the Job reaches a terminal phase.
func runPasswordJob(config passwordChangerConfig, spec passwordJobSpec) error {
	ctx := context.Background()
	timeout := config.JobTimeout
	if timeout <= 0 {
		timeout = passwordJobTimeout
	}

	container, err := passwordJobContainer(config.Pod, config.Container)
	if err != nil {
		return err
	}
	if config.Pod.Status.PodIP == "" {
		return fmt.Errorf("target Pod %s/%s has no IP", config.Namespace, config.Pod.Name)
	}

	name := passwordJobSecretName(spec)
	resourceLabels := map[string]string{
		"app.kubernetes.io/managed-by": "kbcli",
		"app.kubernetes.io/part-of":    config.Pod.Labels[constant.AppInstanceLabelKey],
	}
	scriptSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: config.Namespace,
			Name:      name,
			Labels:    resourceLabels,
		},
		Data: passwordJobSecretData(spec),
	}
	if _, err = config.Client.CoreV1().Secrets(config.Namespace).Create(ctx, scriptSecret, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create temporary password Job Secret %s/%s: %w", config.Namespace, name, err)
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: config.Namespace,
			Name:      name,
			Labels:    resourceLabels,
		},
		Spec: batchv1.JobSpec{
			ActiveDeadlineSeconds:   pointer.Int64(int64(timeout.Seconds()) + 1),
			BackoffLimit:            pointer.Int32(0),
			TTLSecondsAfterFinished: pointer.Int32(60),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: resourceLabels,
				},
				Spec: corev1.PodSpec{
					RestartPolicy:    corev1.RestartPolicyNever,
					ImagePullSecrets: config.Pod.Spec.ImagePullSecrets,
					Containers: []corev1.Container{{
						Name:            passwordJobContainerName,
						Image:           container.Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         spec.command,
						Env:             passwordJobEnv(spec, name),
						VolumeMounts: []corev1.VolumeMount{{
							Name:      passwordJobScriptVolumeName,
							MountPath: passwordJobScriptMountPath,
							ReadOnly:  true,
						}},
					}},
					Volumes: []corev1.Volume{{
						Name: passwordJobScriptVolumeName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: name,
								Items: []corev1.KeyToPath{{
									Key:  passwordJobScriptKey,
									Path: spec.scriptName,
								}},
							},
						},
					}},
				},
			},
		},
	}
	if _, err = config.Client.BatchV1().Jobs(config.Namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		_ = config.Client.CoreV1().Secrets(config.Namespace).Delete(ctx, name, metav1.DeleteOptions{})
		return fmt.Errorf("create temporary password Job %s/%s: %w", config.Namespace, name, err)
	}

	defer func() {
		cleanupPasswordJobResources(ctx, config, name)
	}()

	err = wait.PollUntilContextTimeout(ctx, passwordJobPollInterval, timeout, true, func(ctx context.Context) (bool, error) {
		current, err := config.Client.BatchV1().Jobs(config.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, condition := range current.Status.Conditions {
			switch {
			case condition.Type == batchv1.JobComplete && condition.Status == corev1.ConditionTrue:
				return true, nil
			case condition.Type == batchv1.JobFailed && condition.Status == corev1.ConditionTrue:
				return false, passwordJobError(ctx, config.Client, config.Namespace, current)
			}
		}
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("temporary password Job %s/%s failed: %w", config.Namespace, name, err)
	}
	return nil
}

func passwordJobSecretName(spec passwordJobSpec) string {
	return fmt.Sprintf("kbcli-change-password-%d", time.Now().UnixNano())
}

func passwordJobSecretData(spec passwordJobSpec) map[string][]byte {
	data := make(map[string][]byte, len(spec.secretData)+1)
	for key, value := range spec.secretData {
		data[key] = value
	}
	data[passwordJobScriptKey] = spec.script
	return data
}

func passwordJobEnv(spec passwordJobSpec, secretName string) []corev1.EnvVar {
	env := make([]corev1.EnvVar, 0, len(spec.env)+len(spec.secretEnv))
	env = append(env, spec.env...)
	for _, secretEnv := range spec.secretEnv {
		env = append(env, corev1.EnvVar{
			Name: secretEnv.name,
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
					Key:                  secretEnv.key,
				},
			},
		})
	}
	return env
}

func passwordJobContainer(pod *corev1.Pod, name string) (*corev1.Container, error) {
	if pod == nil {
		return nil, fmt.Errorf("target Pod is not set")
	}
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return &pod.Spec.Containers[i], nil
		}
	}
	return nil, fmt.Errorf("container %q not found in Pod %s/%s", name, pod.Namespace, pod.Name)
}

func passwordJobError(ctx context.Context, client kubernetes.Interface, namespace string, job *batchv1.Job) error {
	conditionMessage := ""
	for _, condition := range job.Status.Conditions {
		if condition.Type == batchv1.JobFailed && condition.Status == corev1.ConditionTrue {
			conditionMessage = strings.TrimSpace(condition.Reason + ": " + condition.Message)
			break
		}
	}

	selector := labels.SelectorFromSet(labels.Set{"job-name": job.Name}).String()
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err == nil {
		for i := range pods.Items {
			if pods.Items[i].Status.Phase != corev1.PodFailed && pods.Items[i].Status.Phase != corev1.PodSucceeded {
				continue
			}
			request := client.CoreV1().Pods(namespace).GetLogs(pods.Items[i].Name, &corev1.PodLogOptions{
				Container: passwordJobContainerName,
			})
			if log, err := request.Do(ctx).Raw(); err == nil && len(log) != 0 {
				message := strings.TrimSpace(string(log))
				if message != "" {
					if conditionMessage != "" {
						return fmt.Errorf("%s; job log: %s", conditionMessage, message)
					}
					return fmt.Errorf("job log: %s", message)
				}
			}
		}
	}
	if conditionMessage != "" {
		return fmt.Errorf("%s", conditionMessage)
	}
	return fmt.Errorf("job failed without a failure condition")
}

func cleanupPasswordJobResources(ctx context.Context, config passwordChangerConfig, name string) {
	jobErr := config.Client.BatchV1().Jobs(config.Namespace).Delete(ctx, name, metav1.DeleteOptions{})
	secretErr := config.Client.CoreV1().Secrets(config.Namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if jobErr == nil && secretErr == nil {
		return
	}

	out := config.Output
	if out == nil {
		out = io.Discard
	}
	fmt.Fprintf(out, "Warning: failed to clean up temporary password Job resources %s/%s (Job: %v, Secret: %v); the Secret contains password material and should be deleted manually.\n",
		config.Namespace, name, jobErr, secretErr)
}
