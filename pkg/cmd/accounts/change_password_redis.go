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
	"net"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const redisPasswordScript = `set -eu
IFS=,
[ -n "$REDIS_ENDPOINTS" ] || { echo "no Redis endpoints found" >&2; exit 1; }
phase=add
rollback() {
  rc=$?
  trap - EXIT INT TERM
  set +e
  if [ "$phase" = "add" ]; then
    for endpoint in $REDIS_ENDPOINTS; do
      redis_cli_with_auth "$REDISCLI_AUTH" "$endpoint" ACL SETUSER "$REDIS_TARGET_USER" "<$REDIS_NEW_PASSWORD"
      redis_cli_with_auth "$REDISCLI_AUTH" "$endpoint" ACL SAVE
    done
  elif [ "$phase" = "remove" ]; then
    remove_auth="$REDISCLI_AUTH"
    if [ "$REDIS_USER" = "$REDIS_TARGET_USER" ]; then
      remove_auth="$REDIS_NEW_PASSWORD"
    fi
    for endpoint in $REDIS_ENDPOINTS; do
      redis_cli_with_auth "$remove_auth" "$endpoint" ACL SETUSER "$REDIS_TARGET_USER" ">$REDIS_OLD_PASSWORD"
      redis_cli_with_auth "$remove_auth" "$endpoint" ACL SAVE
    done
    for endpoint in $REDIS_ENDPOINTS; do
      redis_cli_with_auth "$REDISCLI_AUTH" "$endpoint" ACL SETUSER "$REDIS_TARGET_USER" "<$REDIS_NEW_PASSWORD"
      redis_cli_with_auth "$REDISCLI_AUTH" "$endpoint" ACL SAVE
    done
  fi
  exit "$rc"
}
trap rollback EXIT INT TERM
redis_cli_with_auth() {
  auth="$1"
  endpoint="$2"
  shift 2
  host="${endpoint%:*}"
  port="${endpoint##*:}"
  redis-cli --raw --no-auth-warning -h "$host" -p "$port" --user "$REDIS_USER" -a "$auth" "$@"
}
for endpoint in $REDIS_ENDPOINTS; do
  redis_cli_with_auth "$REDISCLI_AUTH" "$endpoint" ACL SETUSER "$REDIS_TARGET_USER" ">$REDIS_NEW_PASSWORD"
  redis_cli_with_auth "$REDISCLI_AUTH" "$endpoint" ACL SAVE
done
phase=remove
remove_auth="$REDISCLI_AUTH"
if [ "$REDIS_USER" = "$REDIS_TARGET_USER" ]; then
  remove_auth="$REDIS_NEW_PASSWORD"
fi
for endpoint in $REDIS_ENDPOINTS; do
  redis_cli_with_auth "$remove_auth" "$endpoint" ACL SETUSER "$REDIS_TARGET_USER" "<$REDIS_OLD_PASSWORD"
  redis_cli_with_auth "$remove_auth" "$endpoint" ACL SAVE
done
phase=done
`

// redisPasswordChanger rotates a password in Redis. Redis ACL state is local
// to each node, so it must be updated and saved on every Running Pod in the
// component for clients to use the new password on any Pod.
type redisPasswordChanger struct {
	config passwordChangerConfig
}

func (c *redisPasswordChanger) ChangePassword(request passwordChangeRequest) error {
	endpoints := redisPasswordEndpoints(c.config)
	if c.config.ExecutionMode == passwordExecutionModeExec {
		command := []string{
			"env",
			"REDIS_ENDPOINTS=" + strings.Join(endpoints, ","),
			"REDIS_USER=" + request.AuthUser,
			"REDISCLI_AUTH=" + request.AuthPassword,
			"REDIS_TARGET_USER=" + request.TargetUser,
			"REDIS_OLD_PASSWORD=" + request.TargetOldPassword,
			"REDIS_NEW_PASSWORD=" + request.NewPassword,
			"sh", "-s",
		}
		return executePasswordCommand(c.config, request.PodName, command,
			strings.NewReader(redisPasswordScript), true, "redis-cli")
	}

	return runPasswordJob(c.config, passwordJobSpec{
		command: []string{"sh", passwordJobScriptMountPath + "/rotate-acl.sh"},
		env: []corev1.EnvVar{
			{Name: "REDIS_ENDPOINTS", Value: strings.Join(endpoints, ",")},
		},
		script: []byte(redisPasswordScript),
		secretData: map[string][]byte{
			"auth-user":     []byte(request.AuthUser),
			"auth-password": []byte(request.AuthPassword),
			"target-user":   []byte(request.TargetUser),
			"old-password":  []byte(request.TargetOldPassword),
			"new-password":  []byte(request.NewPassword),
		},
		secretEnv: []passwordJobSecretEnv{
			{name: "REDIS_USER", key: "auth-user"},
			{name: "REDISCLI_AUTH", key: "auth-password"},
			{name: "REDIS_TARGET_USER", key: "target-user"},
			{name: "REDIS_OLD_PASSWORD", key: "old-password"},
			{name: "REDIS_NEW_PASSWORD", key: "new-password"},
		},
		scriptName: "rotate-acl.sh",
	})
}

func redisPasswordEndpoints(config passwordChangerConfig) []string {
	pods := config.Pods
	if len(pods) == 0 && config.Pod != nil {
		pods = []*corev1.Pod{config.Pod}
	}
	endpoints := make([]string, 0, len(pods))
	for _, pod := range pods {
		if pod == nil || pod.Status.PodIP == "" {
			continue
		}
		endpoints = append(endpoints, redisPodEndpoint(*pod, config.Container))
	}
	return endpoints
}

func redisPodEndpoint(pod corev1.Pod, containerName string) string {
	port := int32(6379)
	for i := range pod.Spec.Containers {
		container := pod.Spec.Containers[i]
		if containerName != "" && container.Name != containerName {
			continue
		}
		for _, containerPort := range container.Ports {
			if containerPort.Name == "redis" && containerPort.ContainerPort > 0 {
				return net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(int(containerPort.ContainerPort)))
			}
		}
		if containerName != "" && container.Name == containerName {
			break
		}
	}
	return net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(int(port)))
}
