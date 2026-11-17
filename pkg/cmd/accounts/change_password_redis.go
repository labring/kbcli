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
	"strings"

	corev1 "k8s.io/api/core/v1"
)

type redisPasswordChanger struct {
	config passwordChangerConfig
}

func (c *redisPasswordChanger) ChangePassword(request passwordChangeRequest) error {
	// Remove the old ACL password as the new one is added, otherwise both remain valid.
	newPasswordRule := ">" + request.NewPassword
	if c.config.ExecutionMode == passwordExecutionModeExec {
		command := []string{
			"redis-cli",
			"--raw",
			"--no-auth-warning",
			"-h", "127.0.0.1",
			"--user", request.AuthUser,
			"-a", request.AuthPassword,
			"-x",
			"ACL", "SETUSER", request.TargetUser, "<" + request.TargetOldPassword,
		}
		return executePasswordCommand(c.config, request.PodName, command,
			strings.NewReader(newPasswordRule), true, "redis-cli")
	}

	return runPasswordJob(c.config, passwordJobSpec{
		command: []string{
			"sh", "-c",
			`exec redis-cli --raw --no-auth-warning -h "$REDIS_HOST" --user "$REDIS_USER" -a "$REDISCLI_AUTH" -x ACL SETUSER "$REDIS_TARGET_USER" "<$REDIS_OLD_PASSWORD" < /change-password/password`,
		},
		env: []corev1.EnvVar{
			{Name: "REDIS_HOST", Value: c.config.Pod.Status.PodIP},
		},
		script: []byte(newPasswordRule),
		secretData: map[string][]byte{
			"auth-user":     []byte(request.AuthUser),
			"auth-password": []byte(request.AuthPassword),
			"target-user":   []byte(request.TargetUser),
			"old-password":  []byte(request.TargetOldPassword),
		},
		secretEnv: []passwordJobSecretEnv{
			{name: "REDIS_USER", key: "auth-user"},
			{name: "REDISCLI_AUTH", key: "auth-password"},
			{name: "REDIS_TARGET_USER", key: "target-user"},
			{name: "REDIS_OLD_PASSWORD", key: "old-password"},
		},
		scriptName: "password",
	})
}
