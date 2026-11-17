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
	"strings"

	corev1 "k8s.io/api/core/v1"
)

type postgresPasswordChanger struct {
	config passwordChangerConfig
}

func (c *postgresPasswordChanger) ChangePassword(request passwordChangeRequest) error {
	if c.config.ExecutionMode == passwordExecutionModeExec {
		command := []string{
			"env",
			"PGPASSWORD=" + request.AuthPassword,
			"psql",
			"-X",
			"-v", "ON_ERROR_STOP=1",
			"-h", "127.0.0.1",
			"-U", request.AuthUser,
			"-d", c.config.Database,
		}
		return executePasswordCommand(c.config, request.PodName, command,
			strings.NewReader(buildPostgresPasswordSQL(request.TargetUser, request.NewPassword)), true, "psql")
	}

	return runPasswordJob(c.config, passwordJobSpec{
		command: []string{"psql", "-X", "-v", "ON_ERROR_STOP=1", "-f", passwordJobScriptMountPath + "/script.sql"},
		env: []corev1.EnvVar{
			{Name: "PGHOST", Value: c.config.Pod.Status.PodIP},
			{Name: "PGDATABASE", Value: c.config.Database},
		},
		script: []byte(buildPostgresPasswordSQL(request.TargetUser, request.NewPassword)),
		secretData: map[string][]byte{
			"username": []byte(request.AuthUser),
			"password": []byte(request.AuthPassword),
		},
		secretEnv: []passwordJobSecretEnv{
			{name: "PGUSER", key: "username"},
			{name: "PGPASSWORD", key: "password"},
		},
		scriptName: "script.sql",
	})
}

func buildPostgresPasswordSQL(role, password string) string {
	return "SET standard_conforming_strings = on;\nDO $$ BEGIN IF pg_is_in_recovery() THEN RAISE EXCEPTION 'PostgreSQL is in recovery mode and is not writable'; END IF; END $$;\nALTER ROLE " + quotePostgresIdentifier(role) + " PASSWORD " + quotePostgresLiteral(password) + ";\n"
}

func quotePostgresIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func quotePostgresLiteral(value string) string {
	return `'` + strings.ReplaceAll(value, `'`, `''`) + `'`
}
