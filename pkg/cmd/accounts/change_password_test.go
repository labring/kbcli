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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes/fake"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/remotecommand"

	appsv1alpha1 "github.com/apecloud/kubeblocks/apis/apps/v1alpha1"
	"github.com/apecloud/kubeblocks/pkg/constant"
)

func TestBuildPostgresPasswordSQL(t *testing.T) {
	got := buildPostgresPasswordSQL(`role"name`, `p'ass\word`)
	want := "SET standard_conforming_strings = on;\nDO $$ BEGIN IF pg_is_in_recovery() THEN RAISE EXCEPTION 'PostgreSQL is in recovery mode and is not writable'; END IF; END $$;\nALTER ROLE \"role\"\"name\" PASSWORD 'p''ass\\word';\n"
	if got != want {
		t.Fatalf("buildPostgresPasswordSQL() = %q, want %q", got, want)
	}
}

func TestBuildMySQLPasswordSQL(t *testing.T) {
	got := buildMySQLPasswordSQL(`role"name`, `p'ass\word`)
	want := "SET SESSION sql_mode = CONCAT(@@session.sql_mode, ',NO_BACKSLASH_ESCAPES');\nALTER USER 'role\"name'@'%' IDENTIFIED BY 'p''ass\\word';\n"
	if got != want {
		t.Fatalf("buildMySQLPasswordSQL() = %q, want %q", got, want)
	}
}

func TestPromptPassword(t *testing.T) {
	streams, _, _, _ := genericiooptions.NewTestIOStreams()
	var output bytes.Buffer
	streams.Out = &output
	o := NewChangePasswordOptions(nil, streams)
	passwords := [][]byte{[]byte("new-password"), []byte("new-password")}
	o.readPassword = func() ([]byte, error) {
		password := passwords[0]
		passwords = passwords[1:]
		return password, nil
	}

	if err := o.promptPassword(); err != nil {
		t.Fatalf("promptPassword() error = %v", err)
	}
	if o.Password != "new-password" {
		t.Fatalf("prompted password = %q, want %q", o.Password, "new-password")
	}
	if strings.Contains(output.String(), "new-password") {
		t.Fatalf("prompt output contains the plaintext password: %q", output.String())
	}
}

func TestBuildMongoPasswordScriptEscapesValues(t *testing.T) {
	got := buildMongoPasswordScript("admin", `admin"user`, `a'p\ass`, `root"user`, `p'ass\word`)
	want := `var admin = db.getSiblingDB("admin"); var ping = admin.runCommand({ping: 1}); if (!ping || ping.ok !== 1) { printjson(ping); throw new Error("MongoDB health check failed: ping"); } var hello = admin.runCommand({hello: 1}); if (!hello || hello.ok !== 1) { hello = admin.runCommand({isMaster: 1}); } if (!hello || hello.ok !== 1 || (hello.isWritablePrimary !== true && hello.ismaster !== true)) { printjson(hello); throw new Error("MongoDB is not a writable primary"); } var auth = db.getSiblingDB("admin").auth("admin\"user", "a'p\\ass"); if (!auth) { throw new Error("authentication failed"); } var result = db.getSiblingDB("admin").runCommand({updateUser: "root\"user", pwd: "p'ass\\word"}); if (!result || result.ok !== 1) { printjson(result); throw new Error("updateUser failed"); }`
	if got != want {
		t.Fatalf("buildMongoPasswordScript() = %q, want %q", got, want)
	}
}

func TestValidatePasswordComponentPhase(t *testing.T) {
	if err := validatePasswordComponentPhase("mongodb", appsv1alpha1.RunningClusterCompPhase); err != nil {
		t.Fatalf("validatePasswordComponentPhase() error = %v", err)
	}

	err := validatePasswordComponentPhase("mongodb", appsv1alpha1.UpdatingClusterCompPhase)
	if err == nil || !strings.Contains(err.Error(), "is not running") {
		t.Fatalf("validatePasswordComponentPhase() error = %v, want not-running error", err)
	}
}

func TestSelectPasswordPodPrefersPrimary(t *testing.T) {
	pods := []corev1.Pod{
		passwordTestPod("pg-postgresql-1", "replica", "postgresql"),
		passwordTestPod("pg-postgresql-0", "primary", "postgresql"),
	}

	got, err := selectPasswordPod(pods, "pg", "postgresql")
	if err != nil {
		t.Fatalf("selectPasswordPod() error = %v", err)
	}
	if got.Name != "pg-postgresql-0" {
		t.Fatalf("selectPasswordPod() = %q, want %q", got.Name, "pg-postgresql-0")
	}
}

func TestSelectPasswordPodPrefersMasterRole(t *testing.T) {
	pods := []corev1.Pod{
		passwordTestPod("pg-redis-1", "secondary", "redis"),
		passwordTestPod("pg-redis-0", "master", "redis"),
	}

	got, err := selectPasswordPod(pods, "pg", "redis")
	if err != nil {
		t.Fatalf("selectPasswordPod() error = %v", err)
	}
	if got.Name != "pg-redis-0" {
		t.Fatalf("selectPasswordPod() = %q, want %q", got.Name, "pg-redis-0")
	}
}

func TestSelectPasswordPodRejectsAmbiguousFallback(t *testing.T) {
	pods := []corev1.Pod{
		passwordTestPod("pg-postgresql-0", "", "postgresql"),
		passwordTestPod("pg-postgresql-1", "", "postgresql"),
	}

	_, err := selectPasswordPod(pods, "pg", "postgresql")
	if err == nil || !strings.Contains(err.Error(), "pass --instance explicitly") {
		t.Fatalf("selectPasswordPod() error = %v, want an ambiguity error", err)
	}
}

func TestFindTargetPasswordSecretUsesDefaultCandidates(t *testing.T) {
	secret := passwordTestSecret("pg-conn-credential", "postgres", "old-password")
	client := fake.NewSimpleClientset(secret)

	got, err := findTargetPasswordSecret(context.Background(), client, "default", "pg", "postgresql", "postgres", "")
	if err != nil {
		t.Fatalf("findTargetPasswordSecret() error = %v", err)
	}
	if got.Name != secret.Name {
		t.Fatalf("findTargetPasswordSecret() = %q, want %q", got.Name, secret.Name)
	}
}

func TestFindTargetPasswordSecretUsesMongoConnectionSecret(t *testing.T) {
	secret := passwordTestSecret("mongo-conn-credential", "root", "old-password")
	client := fake.NewSimpleClientset(secret)

	got, err := findTargetPasswordSecret(context.Background(), client, "default", "mongo", "mongodb", "root", "")
	if err != nil {
		t.Fatalf("findTargetPasswordSecret() error = %v", err)
	}
	if got.Name != secret.Name {
		t.Fatalf("findTargetPasswordSecret() = %q, want %q", got.Name, secret.Name)
	}
}

func TestFindTargetPasswordSecretsUsesMongoConnectionAndAccountSecrets(t *testing.T) {
	connectionSecret := passwordTestSecret("mongo-conn-credential", "root", "old-password")
	accountSecret := passwordTestSecret("mongo-mongodb-account-root", "root", "old-password")
	client := fake.NewSimpleClientset(connectionSecret, accountSecret)

	got, err := findTargetPasswordSecrets(context.Background(), client, "default", "mongo", "mongodb", "root", "")
	if err != nil {
		t.Fatalf("findTargetPasswordSecrets() error = %v", err)
	}
	if len(got) != 2 || got[0].Name != connectionSecret.Name || got[1].Name != accountSecret.Name {
		t.Fatalf("findTargetPasswordSecrets() = %v, want [%q %q]", passwordSecretNames(got), connectionSecret.Name, accountSecret.Name)
	}
}

func TestFindTargetPasswordSecretUsesMySQLConnectionSecret(t *testing.T) {
	secret := passwordTestSecret("mysql-conn-credential", "root", "old-password")
	client := fake.NewSimpleClientset(secret)

	got, err := findTargetPasswordSecret(context.Background(), client, "default", "mysql", "mysql", "root", "")
	if err != nil {
		t.Fatalf("findTargetPasswordSecret() error = %v", err)
	}
	if got.Name != secret.Name {
		t.Fatalf("findTargetPasswordSecret() = %q, want %q", got.Name, secret.Name)
	}
}

func TestFindTargetPasswordSecretUsesRedisConnectionSecret(t *testing.T) {
	secret := passwordTestSecret("redis-conn-credential", "default", "old-password")
	client := fake.NewSimpleClientset(secret)

	got, err := findTargetPasswordSecret(context.Background(), client, "default", "redis", "redis", "default", "")
	if err != nil {
		t.Fatalf("findTargetPasswordSecret() error = %v", err)
	}
	if got.Name != secret.Name {
		t.Fatalf("findTargetPasswordSecret() = %q, want %q", got.Name, secret.Name)
	}
}

func TestFindTargetPasswordSecretUsesAccountSecret(t *testing.T) {
	secret := passwordTestSecret("pg-postgresql-account-app-user", "app_user", "old-password")
	secret.Labels = map[string]string{
		constant.AppInstanceLabelKey:    "pg",
		constant.ClusterAccountLabelKey: "app_user",
	}
	client := fake.NewSimpleClientset(secret)

	got, err := findTargetPasswordSecret(context.Background(), client, "default", "pg", "postgresql", "app_user", "")
	if err != nil {
		t.Fatalf("findTargetPasswordSecret() error = %v", err)
	}
	if got.Name != secret.Name {
		t.Fatalf("findTargetPasswordSecret() = %q, want %q", got.Name, secret.Name)
	}
}

func TestPatchPasswordSecret(t *testing.T) {
	secret := passwordTestSecret("target", "appuser", "old-password")
	client := fake.NewSimpleClientset(secret)

	if err := patchPasswordSecret(context.Background(), client, "default", secret.Name, []byte("new-password")); err != nil {
		t.Fatalf("patchPasswordSecret() error = %v", err)
	}

	got, err := client.CoreV1().Secrets("default").Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get patched Secret: %v", err)
	}
	if string(got.Data[constant.AccountPasswdForSecret]) != "new-password" {
		t.Fatalf("patched password = %q, want %q", got.Data[constant.AccountPasswdForSecret], "new-password")
	}
}

func TestChangePasswordRunUpdatesSecret(t *testing.T) {
	secret := passwordTestSecret("target", "appuser", "old-password")
	client := fake.NewSimpleClientset(secret)
	changer := &recordingPasswordChanger{}
	o := newTestChangePasswordOptions(client, secret, changer)

	if err := o.Run(); err != nil {
		t.Fatalf("ChangePasswordOptions.Run() error = %v", err)
	}
	if len(changer.requests) != 1 {
		t.Fatalf("password change requests = %d, want 1", len(changer.requests))
	}
	if changer.requests[0].TargetOldPassword != "old-password" {
		t.Fatalf("target old password = %q, want %q", changer.requests[0].TargetOldPassword, "old-password")
	}
	if changer.requests[0].NewPassword != "new-password" {
		t.Fatalf("new password = %q, want %q", changer.requests[0].NewPassword, "new-password")
	}

	got, err := client.CoreV1().Secrets("default").Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get updated Secret: %v", err)
	}
	if string(got.Data[constant.AccountPasswdForSecret]) != "new-password" {
		t.Fatalf("updated password = %q, want %q", got.Data[constant.AccountPasswdForSecret], "new-password")
	}
}

func TestChangePasswordRunUpdatesAllTargetSecrets(t *testing.T) {
	connectionSecret := passwordTestSecret("mongo-conn-credential", "appuser", "old-password")
	accountSecret := passwordTestSecret("mongo-mongodb-account-appuser", "appuser", "old-password")
	client := fake.NewSimpleClientset(connectionSecret, accountSecret)
	changer := &recordingPasswordChanger{}
	o := newTestChangePasswordOptions(client, connectionSecret, changer)
	o.targetSecrets = []*corev1.Secret{connectionSecret, accountSecret}
	o.oldPasswords = map[string]string{
		connectionSecret.Name: "old-password",
		accountSecret.Name:    "old-password",
	}

	if err := o.Run(); err != nil {
		t.Fatalf("ChangePasswordOptions.Run() error = %v", err)
	}
	for _, name := range []string{connectionSecret.Name, accountSecret.Name} {
		got, err := client.CoreV1().Secrets("default").Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get updated Secret %s: %v", name, err)
		}
		if string(got.Data[constant.AccountPasswdForSecret]) != "new-password" {
			t.Fatalf("updated password in Secret %s = %q, want %q", name, got.Data[constant.AccountPasswdForSecret], "new-password")
		}
	}
}

func TestChangePasswordRunDeletesImmutableTargetSecret(t *testing.T) {
	connectionSecret := passwordTestSecret("mongo-conn-credential", "appuser", "old-password")
	accountSecret := passwordTestSecret("mongo-mongodb-account-appuser", "appuser", "old-password")
	immutable := true
	accountSecret.Immutable = &immutable
	client := fake.NewSimpleClientset(connectionSecret, accountSecret)
	changer := &recordingPasswordChanger{}
	o := newTestChangePasswordOptions(client, connectionSecret, changer)
	o.targetSecrets = []*corev1.Secret{connectionSecret, accountSecret}
	o.oldPasswords = map[string]string{
		connectionSecret.Name: "old-password",
		accountSecret.Name:    "old-password",
	}

	if err := o.Run(); err != nil {
		t.Fatalf("ChangePasswordOptions.Run() error = %v", err)
	}
	updated, err := client.CoreV1().Secrets("default").Get(context.Background(), connectionSecret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get updated connection Secret: %v", err)
	}
	if string(updated.Data[constant.AccountPasswdForSecret]) != "new-password" {
		t.Fatalf("updated connection password = %q, want %q", updated.Data[constant.AccountPasswdForSecret], "new-password")
	}
	if _, err := client.CoreV1().Secrets("default").Get(context.Background(), accountSecret.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("immutable account Secret lookup error = %v, want NotFound", err)
	}
}

func TestChangePasswordRunWarnsWhenMongoAccountRootSecretDeletionSticks(t *testing.T) {
	connectionSecret := passwordTestSecret("mongo-conn-credential", "root", "old-password")
	accountSecret := passwordTestSecret("mongo-mongodb-account-root", "root", "old-password")
	accountSecret.Immutable = boolptr(true)
	accountSecret.UID = "old-account-root"
	client := fake.NewSimpleClientset(connectionSecret, accountSecret)
	changer := &recordingPasswordChanger{}
	o := newTestChangePasswordOptions(client, connectionSecret, changer)
	o.CharType = "mongodb"
	o.ClusterName = "mongo"
	o.ComponentName = "mongodb"
	o.UserName = "root"
	o.targetSecrets = []*corev1.Secret{connectionSecret, accountSecret}
	o.oldPasswords = map[string]string{
		connectionSecret.Name: "old-password",
		accountSecret.Name:    "old-password",
	}
	o.AccountRootSecretWaitTimeout = 5 * time.Millisecond
	var output bytes.Buffer
	o.Out = &output

	if err := o.Run(); err != nil {
		t.Fatalf("ChangePasswordOptions.Run() error = %v", err)
	}
	if !strings.Contains(output.String(), "password changed successfully") {
		t.Fatalf("output = %q, want success message", output.String())
	}
	if !strings.Contains(output.String(), "kubectl patch secret mongo-mongodb-account-root -n default") {
		t.Fatalf("output = %q, want account-root finalizer patch command", output.String())
	}
}

func TestChangePasswordRunSupportsOnlyImmutableMongoAccountRootSecret(t *testing.T) {
	accountSecret := passwordTestSecret("mongo-mongodb-account-root", "root", "old-password")
	accountSecret.Immutable = boolptr(true)
	accountSecret.UID = "old-account-root"
	client := fake.NewSimpleClientset(accountSecret)
	changer := &recordingPasswordChanger{}
	o := newTestChangePasswordOptions(client, accountSecret, changer)
	o.CharType = "mongodb"
	o.ClusterName = "mongo"
	o.ComponentName = "mongodb"
	o.UserName = "root"
	o.targetSecrets = []*corev1.Secret{accountSecret}
	o.oldPasswords = map[string]string{accountSecret.Name: "old-password"}
	o.AccountRootSecretWaitTimeout = 5 * time.Millisecond

	if err := o.Run(); err != nil {
		t.Fatalf("ChangePasswordOptions.Run() error = %v", err)
	}
	source, err := client.CoreV1().Secrets("default").Get(context.Background(), "mongo-conn-credential", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get MongoDB legacy connection Secret: %v", err)
	}
	if string(source.Data[constant.AccountNameForSecret]) != "root" {
		t.Fatalf("legacy connection username = %q, want %q", source.Data[constant.AccountNameForSecret], "root")
	}
	if string(source.Data[constant.AccountPasswdForSecret]) != "new-password" {
		t.Fatalf("legacy connection password = %q, want %q", source.Data[constant.AccountPasswdForSecret], "new-password")
	}
}

func TestWaitForMongoAccountRootSecretRecreated(t *testing.T) {
	oldSecret := passwordTestSecret("mongo-mongodb-account-root", "root", "old-password")
	oldSecret.UID = "old-account-root"
	newSecret := oldSecret.DeepCopy()
	newSecret.UID = "new-account-root"
	newSecret.Data[constant.AccountPasswdForSecret] = []byte("new-password")
	client := fake.NewSimpleClientset(oldSecret)
	getCount := 0
	client.PrependReactor("get", "secrets", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		getCount++
		if getCount == 1 {
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, oldSecret.Name)
		}
		return true, newSecret, nil
	})

	if err := waitForMongoAccountRootSecretRecreated(context.Background(), client, "default", oldSecret.Name, oldSecret.UID, []byte("new-password"), time.Second, time.Millisecond); err != nil {
		t.Fatalf("waitForMongoAccountRootSecretRecreated() error = %v", err)
	}
}

func TestWaitForMongoAccountRootSecretRecreatedTimesOut(t *testing.T) {
	secret := passwordTestSecret("mongo-mongodb-account-root", "root", "old-password")
	secret.UID = "old-account-root"
	now := metav1.Now()
	secret.DeletionTimestamp = &now
	client := fake.NewSimpleClientset(secret)

	err := waitForMongoAccountRootSecretRecreated(context.Background(), client, "default", secret.Name, secret.UID, []byte("new-password"), 5*time.Millisecond, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "was not deleted and recreated") {
		t.Fatalf("waitForMongoAccountRootSecretRecreated() error = %v, want timeout error", err)
	}
}

func boolptr(value bool) *bool {
	return &value
}

func TestChangePasswordRunRollsBackWhenSecretUpdateFails(t *testing.T) {
	client := fake.NewSimpleClientset()
	secret := passwordTestSecret("target", "appuser", "old-password")
	changer := &recordingPasswordChanger{}
	o := newTestChangePasswordOptions(client, secret, changer)

	err := o.Run()
	if err == nil || !strings.Contains(err.Error(), "password was rolled back") {
		t.Fatalf("ChangePasswordOptions.Run() error = %v, want rollback error", err)
	}
	if len(changer.requests) != 2 {
		t.Fatalf("password change requests = %d, want 2", len(changer.requests))
	}
	if changer.requests[1].AuthPassword != "admin-password" {
		t.Fatalf("rollback auth password = %q, want %q", changer.requests[1].AuthPassword, "admin-password")
	}
	if changer.requests[1].TargetOldPassword != "new-password" {
		t.Fatalf("rollback target old password = %q, want %q", changer.requests[1].TargetOldPassword, "new-password")
	}
	if changer.requests[1].NewPassword != "old-password" {
		t.Fatalf("rollback new password = %q, want %q", changer.requests[1].NewPassword, "old-password")
	}
}

func TestNewPasswordChangerRejectsUnsupportedDatabase(t *testing.T) {
	if _, err := newPasswordChanger("oracle", passwordChangerConfig{}); err == nil {
		t.Fatal("newPasswordChanger() should reject unsupported databases")
	}
}

func TestNewPasswordChangerSupportsMySQLAndRedis(t *testing.T) {
	mysqlChanger, err := newPasswordChanger("mysql", passwordChangerConfig{})
	if err != nil {
		t.Fatalf("newPasswordChanger(mysql) error = %v", err)
	}
	if _, ok := mysqlChanger.(*mysqlPasswordChanger); !ok {
		t.Fatalf("newPasswordChanger(mysql) type = %T, want *mysqlPasswordChanger", mysqlChanger)
	}

	redisChanger, err := newPasswordChanger("redis", passwordChangerConfig{})
	if err != nil {
		t.Fatalf("newPasswordChanger(redis) error = %v", err)
	}
	if _, ok := redisChanger.(*redisPasswordChanger); !ok {
		t.Fatalf("newPasswordChanger(redis) type = %T, want *redisPasswordChanger", redisChanger)
	}
}

func TestNewPasswordChangerSupportsMongoDB(t *testing.T) {
	for _, characterType := range []string{"mongo", "mongodb"} {
		changer, err := newPasswordChanger(characterType, passwordChangerConfig{})
		if err != nil {
			t.Fatalf("newPasswordChanger(%q) error = %v", characterType, err)
		}
		if _, ok := changer.(*mongoPasswordChanger); !ok {
			t.Fatalf("newPasswordChanger(%q) type = %T, want *mongoPasswordChanger", characterType, changer)
		}
	}
}

func TestDefaultPasswordValuesForCharacterType(t *testing.T) {
	if got := defaultPasswordUserForCharacterType("mongodb"); got != defaultMongoPasswordUser {
		t.Fatalf("MongoDB default user = %q, want %q", got, defaultMongoPasswordUser)
	}
	if got := defaultPasswordDatabaseForCharacterType("mongodb"); got != defaultMongoPasswordDatabase {
		t.Fatalf("MongoDB default database = %q, want %q", got, defaultMongoPasswordDatabase)
	}
	if got := defaultPasswordUserForCharacterType("postgresql"); got != defaultPasswordUser {
		t.Fatalf("PostgreSQL default user = %q, want %q", got, defaultPasswordUser)
	}
	if got := defaultPasswordDatabaseForCharacterType("postgresql"); got != defaultPasswordDatabase {
		t.Fatalf("PostgreSQL default database = %q, want %q", got, defaultPasswordDatabase)
	}
	if got := defaultPasswordUserForCharacterType("mysql"); got != defaultMySQLPasswordUser {
		t.Fatalf("MySQL default user = %q, want %q", got, defaultMySQLPasswordUser)
	}
	if got := defaultPasswordDatabaseForCharacterType("mysql"); got != defaultMySQLPasswordDatabase {
		t.Fatalf("MySQL default database = %q, want %q", got, defaultMySQLPasswordDatabase)
	}
	if got := defaultPasswordUserForCharacterType("redis"); got != defaultRedisPasswordUser {
		t.Fatalf("Redis default user = %q, want %q", got, defaultRedisPasswordUser)
	}
	if got := defaultPasswordDatabaseForCharacterType("redis"); got != defaultRedisPasswordDatabase {
		t.Fatalf("Redis default database = %q, want %q", got, defaultRedisPasswordDatabase)
	}
}

type recordingPasswordChanger struct {
	requests []passwordChangeRequest
}

func (c *recordingPasswordChanger) ChangePassword(request passwordChangeRequest) error {
	c.requests = append(c.requests, request)
	return nil
}

func newTestChangePasswordOptions(client *fake.Clientset, secret *corev1.Secret, changer passwordChanger) *ChangePasswordOptions {
	streams, _, _, _ := genericiooptions.NewTestIOStreams()
	o := NewChangePasswordOptions(nil, streams)
	o.kubeClient = client
	o.targetSecret = secret
	o.Password = "new-password"
	o.UserName = "appuser"
	o.Namespace = "default"
	o.PodName = "pg-postgresql-0"
	o.authUser = "admin"
	o.authPassword = "admin-password"
	o.oldPassword = "old-password"
	o.passwordChanger = changer
	o.Out = io.Discard
	o.ErrOut = io.Discard
	return o
}

func passwordTestPod(name, role, component string) corev1.Pod {
	labels := map[string]string{
		constant.AppInstanceLabelKey:    "pg",
		constant.KBAppComponentLabelKey: component,
	}
	if role != "" {
		labels[constant.RoleLabelKey] = role
	}
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func passwordTestSecret(name, user, password string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Data: map[string][]byte{
			constant.AccountNameForSecret:   []byte(user),
			constant.AccountPasswdForSecret: []byte(password),
		},
	}
}

func passwordSecretNames(secrets []*corev1.Secret) []string {
	names := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		names = append(names, secret.Name)
	}
	return names
}

func TestPostgresPasswordChangerUsesTemporaryJobWithoutExec(t *testing.T) {
	client := fake.NewSimpleClientset()
	completePasswordJobsImmediately(client)
	pod := passwordTestPod("pg-postgresql-0", "primary", "postgresql")
	pod.Namespace = "default"
	pod.Status.PodIP = "10.0.0.8"
	pod.Spec.Containers = []corev1.Container{{Name: "postgresql", Image: "postgres:test"}}
	pod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "registry-secret"}}

	changer, err := newPasswordChanger("postgresql", passwordChangerConfig{
		Client:     client,
		Namespace:  "default",
		Database:   "postgres",
		Container:  "postgresql",
		Pod:        &pod,
		Output:     io.Discard,
		JobTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newPasswordChanger() error = %v", err)
	}

	if err = changer.ChangePassword(passwordChangeRequest{
		AuthUser:     "admin",
		AuthPassword: "old-password",
		TargetUser:   "appuser",
		NewPassword:  "new-password",
	}); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}

	job := createdPasswordJob(t, client)
	if job == nil {
		t.Fatal("temporary password Job was not created")
	}
	command := job.Spec.Template.Spec.Containers[0].Command
	if len(command) == 0 || command[0] != "psql" {
		t.Fatalf("temporary PostgreSQL Job command = %v, want psql", command)
	}
	foundScript := false
	for _, arg := range command[1:] {
		if arg == passwordJobScriptMountPath+"/script.sql" {
			foundScript = true
			break
		}
	}
	if !foundScript {
		t.Fatalf("temporary PostgreSQL Job command does not execute the mounted script: %v", command)
	}
	if job.Spec.Template.Spec.Containers[0].Image != "postgres:test" {
		t.Fatalf("temporary Job image = %q, want %q", job.Spec.Template.Spec.Containers[0].Image, "postgres:test")
	}
	if job.Spec.Template.Spec.ImagePullSecrets[0].Name != "registry-secret" {
		t.Fatalf("temporary Job did not inherit the target Pod image pull Secret")
	}
	jobObject := string(mustMarshalJSON(t, job))
	for _, password := range []string{"old-password", "new-password"} {
		if strings.Contains(jobObject, password) {
			t.Fatalf("temporary Job contains plaintext password %q", password)
		}
	}

	scriptSecret := createdPasswordSecret(t, client)
	if scriptSecret.Name != job.Name {
		t.Fatalf("temporary Secret name = %q, want Job name %q", scriptSecret.Name, job.Name)
	}
	if string(scriptSecret.Data["username"]) != "admin" || string(scriptSecret.Data["password"]) != "old-password" {
		t.Fatal("temporary PostgreSQL Secret does not contain the supplied rollback credentials")
	}

	var hasUserRef, hasPasswordRef bool
	for _, env := range job.Spec.Template.Spec.Containers[0].Env {
		if env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil || env.ValueFrom.SecretKeyRef.Name != job.Name {
			continue
		}
		if env.Name == "PGUSER" && env.ValueFrom.SecretKeyRef.Key == "username" {
			hasUserRef = true
		}
		if env.Name == "PGPASSWORD" && env.ValueFrom.SecretKeyRef.Key == "password" {
			hasPasswordRef = true
		}
	}
	if !hasUserRef || !hasPasswordRef {
		t.Fatal("temporary Job does not load PostgreSQL credentials from its temporary Secret")
	}

	assertNoPasswordExec(t, client)
	assertTemporaryPasswordResourcesDeleted(t, client, job.Name)
}

func TestMongoPasswordChangerUsesTemporaryJobWithoutExec(t *testing.T) {
	client := fake.NewSimpleClientset()
	completePasswordJobsImmediately(client)
	pod := passwordTestPod("mongo-mongodb-0", "primary", "mongodb")
	pod.Namespace = "default"
	pod.Status.PodIP = "10.0.0.9"
	pod.Spec.Containers = []corev1.Container{{Name: "mongodb", Image: "mongo:test"}}

	changer, err := newPasswordChanger("mongodb", passwordChangerConfig{
		Client:     client,
		Namespace:  "default",
		Database:   "admin",
		Container:  "mongodb",
		Pod:        &pod,
		Output:     io.Discard,
		JobTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newPasswordChanger() error = %v", err)
	}

	if err = changer.ChangePassword(passwordChangeRequest{
		AuthUser:     "root",
		AuthPassword: "old-password",
		TargetUser:   "appuser",
		NewPassword:  "new-password",
	}); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}

	job := createdPasswordJob(t, client)
	if job == nil {
		t.Fatal("temporary password Job was not created")
	}
	jobObject := string(mustMarshalJSON(t, job))
	for _, password := range []string{"old-password", "new-password"} {
		if strings.Contains(jobObject, password) {
			t.Fatalf("temporary Job contains plaintext password %q", password)
		}
	}
	scriptSecret := createdPasswordSecret(t, client)
	if scriptSecret.Name != job.Name {
		t.Fatalf("temporary Secret name = %q, want Job name %q", scriptSecret.Name, job.Name)
	}
	if !strings.Contains(string(scriptSecret.Data[passwordJobScriptKey]), "new-password") {
		t.Fatal("temporary MongoDB Secret does not contain the password-change script")
	}

	command := job.Spec.Template.Spec.Containers[0].Command
	if len(command) != 3 || command[0] != "sh" || command[1] != "-c" || !strings.Contains(command[2], "/change-password/script.js") {
		t.Fatalf("temporary MongoDB Job command = %v, want a shell command that reads the mounted script", command)
	}

	assertNoPasswordExec(t, client)
	assertTemporaryPasswordResourcesDeleted(t, client, job.Name)
}

func TestMySQLPasswordChangerUsesTemporaryJobWithoutExec(t *testing.T) {
	client := fake.NewSimpleClientset()
	completePasswordJobsImmediately(client)
	pod := passwordTestPod("mysql-mysql-0", "leader", "mysql")
	pod.Namespace = "default"
	pod.Status.PodIP = "10.0.0.10"
	pod.Spec.Containers = []corev1.Container{{Name: "mysql", Image: "apecloud/mysql:test"}}

	changer, err := newPasswordChanger("mysql", passwordChangerConfig{
		Client:     client,
		Namespace:  "default",
		Database:   "mysql",
		Container:  "mysql",
		Pod:        &pod,
		Output:     io.Discard,
		JobTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newPasswordChanger() error = %v", err)
	}

	if err = changer.ChangePassword(passwordChangeRequest{
		AuthUser:          "root",
		AuthPassword:      "admin-password",
		TargetUser:        "appuser",
		TargetOldPassword: "target-old-secret",
		NewPassword:       "new-password",
	}); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}

	job := createdPasswordJob(t, client)
	if job == nil {
		t.Fatal("temporary password Job was not created")
	}
	command := job.Spec.Template.Spec.Containers[0].Command
	if len(command) != 3 || command[0] != "sh" || command[1] != "-c" ||
		!strings.Contains(command[2], "mysql") || !strings.Contains(command[2], passwordJobScriptMountPath+"/script.sql") {
		t.Fatalf("temporary MySQL Job command = %v, want a shell command that reads the mounted SQL script", command)
	}
	jobObject := string(mustMarshalJSON(t, job))
	for _, password := range []string{"admin-password", "target-old-secret", "new-password"} {
		if strings.Contains(jobObject, password) {
			t.Fatalf("temporary Job contains plaintext password %q", password)
		}
	}

	scriptSecret := createdPasswordSecret(t, client)
	if scriptSecret.Name != job.Name {
		t.Fatalf("temporary Secret name = %q, want Job name %q", scriptSecret.Name, job.Name)
	}
	if string(scriptSecret.Data["username"]) != "root" || string(scriptSecret.Data["password"]) != "admin-password" {
		t.Fatal("temporary MySQL Secret does not contain the supplied credentials")
	}
	if !strings.Contains(string(scriptSecret.Data[passwordJobScriptKey]), `ALTER USER 'appuser'@'%'`) {
		t.Fatal("temporary MySQL Secret does not contain the password-change SQL")
	}
	assertPasswordJobSecretEnv(t, job, "MYSQL_USER", "username")
	assertPasswordJobSecretEnv(t, job, "MYSQL_PWD", "password")
	assertNoPasswordExec(t, client)
	assertTemporaryPasswordResourcesDeleted(t, client, job.Name)
}

func TestRedisPasswordChangerUsesTemporaryJobWithoutExec(t *testing.T) {
	client := fake.NewSimpleClientset()
	completePasswordJobsImmediately(client)
	pod := passwordTestPod("redis-redis-0", "master", "redis")
	pod.Namespace = "default"
	pod.Status.PodIP = "10.0.0.11"
	pod.Spec.Containers = []corev1.Container{{Name: "redis", Image: "redis:test"}}

	changer, err := newPasswordChanger("redis", passwordChangerConfig{
		Client:     client,
		Namespace:  "default",
		Database:   "0",
		Container:  "redis",
		Pod:        &pod,
		Output:     io.Discard,
		JobTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newPasswordChanger() error = %v", err)
	}

	if err = changer.ChangePassword(passwordChangeRequest{
		AuthUser:          "default",
		AuthPassword:      "admin-password",
		TargetUser:        "default",
		TargetOldPassword: "target-old-secret",
		NewPassword:       "new-password",
	}); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}

	job := createdPasswordJob(t, client)
	if job == nil {
		t.Fatal("temporary password Job was not created")
	}
	command := job.Spec.Template.Spec.Containers[0].Command
	if len(command) != 3 || command[0] != "sh" || command[1] != "-c" ||
		!strings.Contains(command[2], "redis-cli") || !strings.Contains(command[2], "/change-password/password") {
		t.Fatalf("temporary Redis Job command = %v, want a shell command that reads the mounted password", command)
	}
	jobObject := string(mustMarshalJSON(t, job))
	for _, password := range []string{"admin-password", "target-old-secret", "new-password"} {
		if strings.Contains(jobObject, password) {
			t.Fatalf("temporary Job contains plaintext password %q", password)
		}
	}

	scriptSecret := createdPasswordSecret(t, client)
	if scriptSecret.Name != job.Name {
		t.Fatalf("temporary Secret name = %q, want Job name %q", scriptSecret.Name, job.Name)
	}
	if string(scriptSecret.Data[passwordJobScriptKey]) != ">new-password" {
		t.Fatalf("temporary Redis password rule = %q, want %q", scriptSecret.Data[passwordJobScriptKey], ">new-password")
	}
	if string(scriptSecret.Data["auth-password"]) != "admin-password" || string(scriptSecret.Data["old-password"]) != "target-old-secret" {
		t.Fatal("temporary Redis Secret does not contain authentication and rollback passwords")
	}
	assertPasswordJobSecretEnv(t, job, "REDIS_USER", "auth-user")
	assertPasswordJobSecretEnv(t, job, "REDISCLI_AUTH", "auth-password")
	assertPasswordJobSecretEnv(t, job, "REDIS_TARGET_USER", "target-user")
	assertPasswordJobSecretEnv(t, job, "REDIS_OLD_PASSWORD", "old-password")
	assertNoPasswordExec(t, client)
	assertTemporaryPasswordResourcesDeleted(t, client, job.Name)
}

func TestPostgresPasswordChangerSupportsExecExecutor(t *testing.T) {
	client := fake.NewSimpleClientset()
	pod := passwordTestPod("pg-postgresql-0", "primary", "postgresql")
	pod.Namespace = "default"
	pod.Spec.Containers = []corev1.Container{{Name: "postgresql", Image: "postgres:test"}}
	executor := &recordingPasswordExecutor{}
	changer, err := newPasswordChanger("postgresql", passwordChangerConfig{
		Client:        client,
		Namespace:     "default",
		Database:      "postgres",
		Container:     "postgresql",
		Pod:           &pod,
		Config:        &rest.Config{},
		RESTClient:    passwordExecRESTClient(t),
		Executor:      executor,
		ExecutionMode: passwordExecutionModeExec,
		Output:        io.Discard,
		JobTimeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("newPasswordChanger() error = %v", err)
	}

	if err = changer.ChangePassword(passwordChangeRequest{
		PodName:      pod.Name,
		AuthUser:     "admin",
		AuthPassword: "old-password",
		TargetUser:   "appuser",
		NewPassword:  "new-password",
	}); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}

	if executor.url == nil {
		t.Fatal("exec executor was not invoked")
	}
	if executor.url.Path != "/api/v1/namespaces/default/pods/pg-postgresql-0/exec" {
		t.Fatalf("exec URL path = %q", executor.url.Path)
	}
	assertExecQueryValue(t, executor.url, "container", "postgresql")
	assertExecQueryValues(t, executor.url, "command", []string{"env", "psql"})
	if !strings.Contains(executor.stdin.String(), `ALTER ROLE "appuser" PASSWORD 'new-password';`) {
		t.Fatalf("exec stdin does not contain the PostgreSQL change: %q", executor.stdin.String())
	}
	assertNoPasswordJobResources(t, client)
}

func TestMongoPasswordChangerSupportsExecExecutor(t *testing.T) {
	client := fake.NewSimpleClientset()
	pod := passwordTestPod("mongo-mongodb-0", "primary", "mongodb")
	pod.Namespace = "default"
	pod.Spec.Containers = []corev1.Container{{Name: "mongodb", Image: "mongo:test"}}
	executor := &recordingPasswordExecutor{}
	changer, err := newPasswordChanger("mongodb", passwordChangerConfig{
		Client:        client,
		Namespace:     "default",
		Database:      "admin",
		Container:     "mongodb",
		Pod:           &pod,
		Config:        &rest.Config{},
		RESTClient:    passwordExecRESTClient(t),
		Executor:      executor,
		ExecutionMode: passwordExecutionModeExec,
		Output:        io.Discard,
		JobTimeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("newPasswordChanger() error = %v", err)
	}

	if err = changer.ChangePassword(passwordChangeRequest{
		PodName:      pod.Name,
		AuthUser:     "root",
		AuthPassword: "old-password",
		TargetUser:   "appuser",
		NewPassword:  "new-password",
	}); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}

	if executor.url == nil {
		t.Fatal("exec executor was not invoked")
	}
	if executor.url.Path != "/api/v1/namespaces/default/pods/mongo-mongodb-0/exec" {
		t.Fatalf("exec URL path = %q", executor.url.Path)
	}
	assertExecQueryValue(t, executor.url, "container", "mongodb")
	assertExecQueryValues(t, executor.url, "command", []string{"sh", "-c"})
	if !strings.Contains(executor.stdin.String(), `updateUser: "appuser"`) {
		t.Fatalf("exec stdin does not contain the MongoDB change: %q", executor.stdin.String())
	}
	assertNoPasswordJobResources(t, client)
}

func TestMySQLPasswordChangerSupportsExecExecutor(t *testing.T) {
	client := fake.NewSimpleClientset()
	pod := passwordTestPod("mysql-mysql-0", "leader", "mysql")
	pod.Namespace = "default"
	pod.Spec.Containers = []corev1.Container{{Name: "mysql", Image: "apecloud/mysql:test"}}
	executor := &recordingPasswordExecutor{}
	changer, err := newPasswordChanger("mysql", passwordChangerConfig{
		Client:        client,
		Namespace:     "default",
		Database:      "mysql",
		Container:     "mysql",
		Pod:           &pod,
		Config:        &rest.Config{},
		RESTClient:    passwordExecRESTClient(t),
		Executor:      executor,
		ExecutionMode: passwordExecutionModeExec,
		Output:        io.Discard,
		JobTimeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("newPasswordChanger() error = %v", err)
	}

	if err = changer.ChangePassword(passwordChangeRequest{
		PodName:           pod.Name,
		AuthUser:          "root",
		AuthPassword:      "old-password",
		TargetUser:        "appuser",
		TargetOldPassword: "old-password",
		NewPassword:       "new-password",
	}); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}

	if executor.url == nil {
		t.Fatal("exec executor was not invoked")
	}
	assertExecQueryValue(t, executor.url, "container", "mysql")
	assertExecQueryValues(t, executor.url, "command", []string{"env", "mysql"})
	if !strings.Contains(executor.stdin.String(), `ALTER USER 'appuser'@'%'`) {
		t.Fatalf("exec stdin does not contain the MySQL change: %q", executor.stdin.String())
	}
	assertNoPasswordJobResources(t, client)
}

func TestRedisPasswordChangerSupportsExecExecutor(t *testing.T) {
	client := fake.NewSimpleClientset()
	pod := passwordTestPod("redis-redis-0", "master", "redis")
	pod.Namespace = "default"
	pod.Spec.Containers = []corev1.Container{{Name: "redis", Image: "redis:test"}}
	executor := &recordingPasswordExecutor{}
	changer, err := newPasswordChanger("redis", passwordChangerConfig{
		Client:        client,
		Namespace:     "default",
		Database:      "0",
		Container:     "redis",
		Pod:           &pod,
		Config:        &rest.Config{},
		RESTClient:    passwordExecRESTClient(t),
		Executor:      executor,
		ExecutionMode: passwordExecutionModeExec,
		Output:        io.Discard,
		JobTimeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("newPasswordChanger() error = %v", err)
	}

	if err = changer.ChangePassword(passwordChangeRequest{
		PodName:           pod.Name,
		AuthUser:          "default",
		AuthPassword:      "old-password",
		TargetUser:        "default",
		TargetOldPassword: "old-password",
		NewPassword:       "new-password",
	}); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}

	if executor.url == nil {
		t.Fatal("exec executor was not invoked")
	}
	assertExecQueryValue(t, executor.url, "container", "redis")
	assertExecQueryValues(t, executor.url, "command", []string{"redis-cli", "--raw"})
	if executor.stdin.String() != ">new-password" {
		t.Fatalf("exec stdin = %q, want the new Redis password rule", executor.stdin.String())
	}
	assertNoPasswordJobResources(t, client)
}

func TestChangePasswordValidateExecutor(t *testing.T) {
	o := &ChangePasswordOptions{}
	if err := o.Validate(); err != nil {
		t.Fatalf("Validate() with default executor error = %v", err)
	}
	if o.ExecutionMode != passwordExecutionModeJob {
		t.Fatalf("default executor = %q, want %q", o.ExecutionMode, passwordExecutionModeJob)
	}

	o.ExecutionMode = "invalid"
	err := o.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid executor") {
		t.Fatalf("Validate() invalid executor error = %v", err)
	}
}

func completePasswordJobsImmediately(client *fake.Clientset) {
	client.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
		now := metav1.Now()
		job.Status.Conditions = []batchv1.JobCondition{{
			Type:               batchv1.JobComplete,
			Status:             corev1.ConditionTrue,
			LastProbeTime:      now,
			LastTransitionTime: now,
		}}
		// Return false so the fake client's default reactor stores the modified Job.
		return false, nil, nil
	})
}

func createdPasswordJob(t *testing.T, client *fake.Clientset) *batchv1.Job {
	t.Helper()
	for _, action := range client.Actions() {
		if action.GetVerb() != "create" || action.GetResource().Resource != "jobs" || action.GetSubresource() != "" {
			continue
		}
		return action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
	}
	return nil
}

func createdPasswordSecret(t *testing.T, client *fake.Clientset) *corev1.Secret {
	t.Helper()
	for _, action := range client.Actions() {
		if action.GetVerb() != "create" || action.GetResource().Resource != "secrets" || action.GetSubresource() != "" {
			continue
		}
		secret := action.(k8stesting.CreateAction).GetObject().(*corev1.Secret)
		if strings.HasPrefix(secret.Name, "kbcli-change-password-") {
			return secret
		}
	}
	return nil
}

func passwordExecRESTClient(t *testing.T) rest.Interface {
	t.Helper()
	restConfig := &rest.Config{Host: "https://kubernetes.example"}
	restConfig.GroupVersion = &schema.GroupVersion{Version: "v1"}
	restConfig.APIPath = "/api"
	restConfig.NegotiatedSerializer = k8sscheme.Codecs.WithoutConversion()
	client, err := rest.RESTClientFor(restConfig)
	if err != nil {
		t.Fatalf("create REST client: %v", err)
	}
	return client
}

type recordingPasswordExecutor struct {
	url   *url.URL
	stdin strings.Builder
}

func (e *recordingPasswordExecutor) Execute(execURL *url.URL, _ *rest.Config, stdin io.Reader, _, _ io.Writer, _ bool, _ remotecommand.TerminalSizeQueue) error {
	e.url = execURL
	_, err := io.Copy(&e.stdin, stdin)
	return err
}

func assertExecQueryValue(t *testing.T, execURL *url.URL, key, want string) {
	t.Helper()
	if got := execURL.Query().Get(key); got != want {
		t.Fatalf("exec query %s = %q, want %q", key, got, want)
	}
}

func assertExecQueryValues(t *testing.T, execURL *url.URL, key string, wanted []string) {
	t.Helper()
	got := execURL.Query()[key]
	for _, want := range wanted {
		found := false
		for _, value := range got {
			if value == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("exec query %s = %v, want it to contain %q", key, got, want)
		}
	}
}

func assertNoPasswordJobResources(t *testing.T, client *fake.Clientset) {
	t.Helper()
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" && (action.GetResource().Resource == "jobs" || action.GetResource().Resource == "secrets") {
			t.Fatalf("exec mode created a temporary resource: %v", action)
		}
	}
}

func assertPasswordJobSecretEnv(t *testing.T, job *batchv1.Job, name, key string) {
	t.Helper()
	for _, env := range job.Spec.Template.Spec.Containers[0].Env {
		if env.Name != name || env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil {
			continue
		}
		if env.ValueFrom.SecretKeyRef.Name == job.Name && env.ValueFrom.SecretKeyRef.Key == key {
			return
		}
	}
	t.Fatalf("temporary Job does not load %s from temporary Secret key %s", name, key)
}

func assertNoPasswordExec(t *testing.T, client *fake.Clientset) {
	t.Helper()
	for _, action := range client.Actions() {
		if action.GetResource().Resource == "pods" && action.GetSubresource() == "exec" {
			t.Fatalf("password change used the pods/exec subresource: %v", action)
		}
	}
}

func assertTemporaryPasswordResourcesDeleted(t *testing.T, client *fake.Clientset, name string) {
	t.Helper()
	assertDeleted := func(resource string) {
		deleted := false
		for _, action := range client.Actions() {
			if action.GetVerb() == "delete" && action.GetResource().Resource == resource {
				deleted = true
			}
		}
		if !deleted {
			t.Fatalf("temporary password %s %s was not deleted", resource, name)
		}
	}
	assertDeleted("jobs")
	assertDeleted("secrets")
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return data
}
