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

type mysqlPasswordChanger struct {
	config passwordChangerConfig
}

func (c *mysqlPasswordChanger) ChangePassword(request passwordChangeRequest) error {
	if c.config.ExecutionMode == passwordExecutionModeExec {
		command := []string{
			"env",
			"MYSQL_PWD=" + request.AuthPassword,
			"mysql",
			"--batch",
			"--skip-column-names",
			"-h", "127.0.0.1",
			"-u", request.AuthUser,
			"--database=" + c.config.Database,
		}
		return executePasswordCommand(c.config, request.PodName, command,
			strings.NewReader(buildMySQLPasswordSQL(request.TargetUser, request.NewPassword)), true, "mysql")
	}

	return runPasswordJob(c.config, passwordJobSpec{
		command: []string{
			"sh", "-c",
			`exec mysql --batch --skip-column-names -h "$MYSQL_HOST" -u "$MYSQL_USER" --database="$MYSQL_DATABASE" < ` + passwordJobScriptMountPath + `/script.sql`,
		},
		env: []corev1.EnvVar{
			{Name: "MYSQL_HOST", Value: c.config.Pod.Status.PodIP},
			{Name: "MYSQL_DATABASE", Value: c.config.Database},
		},
		script: []byte(buildMySQLPasswordSQL(request.TargetUser, request.NewPassword)),
		secretData: map[string][]byte{
			"username": []byte(request.AuthUser),
			"password": []byte(request.AuthPassword),
		},
		secretEnv: []passwordJobSecretEnv{
			{name: "MYSQL_USER", key: "username"},
			{name: "MYSQL_PWD", key: "password"},
		},
		scriptName: "script.sql",
	})
}

func buildMySQLPasswordSQL(role, password string) string {
	// This mode makes doubling single quotes a safe escaping strategy.
	return "SET SESSION sql_mode = CONCAT(@@session.sql_mode, ',NO_BACKSLASH_ESCAPES');\nALTER USER " + quoteMySQLString(role) + "@'%' IDENTIFIED BY " + quoteMySQLString(password) + ";\n"
}

func quoteMySQLString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
