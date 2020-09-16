package cmd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	charts "github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/tls"
	corev1 "k8s.io/api/core/v1"
)

const (
	upgradeProxyVersion        = "UPGRADE-PROXY-VERSION"
	upgradeControlPlaneVersion = "UPGRADE-CONTROL-PLANE-VERSION"
	upgradeDebugVersion        = "UPGRADE-DEBUG-VERSION"
)

type (
	issuerCerts struct {
		caFile  string
		ca      string
		crtFile string
		crt     string
		keyFile string
		key     string
	}
)

/* Test cases */

/* Most test cases in this file work by first rendering an install manifest
   list, creating a fake k8s client initialized with those manifests, rendering
   an upgrade manifest list, and comparing the install manifests to the upgrade
   manifests. In some cases we expect these manifests to be identical and in
   others there are certain expected differences */

func TestUpgradeDefault(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)
	install, upgrade, err := renderInstallAndUpgrade(t, installOpts, upgradeOpts)
	if err != nil {
		t.Fatal(err)
	}
	// Install and upgrade manifests should be identical except for the version.
	expected := replaceVersions(install.String())
	expectedManifests := parseManifestList(expected)
	upgradeManifests := parseManifestList(upgrade.String())
	for id, diffs := range diffManifestLists(expectedManifests, upgradeManifests) {
		for _, diff := range diffs {
			if ignorableDiff(id, diff) {
				continue
			}
			t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
		}
	}
}

func TestUpgradeHA(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)
	installOpts.highAvailability = true
	install, upgrade, err := renderInstallAndUpgrade(t, installOpts, upgradeOpts)
	if err != nil {
		t.Fatal(err)
	}
	// Install and upgrade manifests should be identical except for the version.
	expected := replaceVersions(install.String())
	expectedManifests := parseManifestList(expected)
	upgradeManifests := parseManifestList(upgrade.String())
	for id, diffs := range diffManifestLists(expectedManifests, upgradeManifests) {
		for _, diff := range diffs {
			if ignorableDiff(id, diff) {
				continue
			}
			t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
		}
	}
}

func TestUpgradeExternalIssuer(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	issuer := generateIssuerCerts(t, true)
	defer issuer.cleanup()

	values := installValues(t, installOpts, nil)
	values.Identity = &linkerd2.Identity{
		Issuer: &linkerd2.Issuer{
			Scheme: string(corev1.SecretTypeTLS),
			TLS: &linkerd2.IssuerTLS{
				CrtPEM: issuer.crt,
				KeyPEM: issuer.key,
			},
		},
	}
	values.Global.IdentityTrustAnchorsPEM = issuer.ca
	install := renderInstall(t, values)
	upgrade, err := renderUpgrade(install.String()+externalIssuerSecret(issuer), upgradeOpts, nil, false)

	if err != nil {
		t.Fatal(err)
	}
	// Install and upgrade manifests should be identical except for the version.
	expected := replaceVersions(install.String())
	expectedManifests := parseManifestList(expected)
	upgradeManifests := parseManifestList(upgrade.String())
	for id, diffs := range diffManifestLists(expectedManifests, upgradeManifests) {
		for _, diff := range diffs {
			if ignorableDiff(id, diff) {
				continue
			}
			t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
		}
	}
}

func TestUpgradeIssuerWithExternalIssuerFails(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	issuer := generateIssuerCerts(t, true)
	defer issuer.cleanup()

	values := installValues(t, installOpts, nil)
	values.Global.IdentityTrustDomain = "cluster.local"
	values.Global.IdentityTrustDomain = issuer.ca
	values.Identity.Issuer.Scheme = string(corev1.SecretTypeTLS)
	values.Identity.Issuer.TLS.CrtPEM = issuer.crt
	values.Identity.Issuer.TLS.KeyPEM = issuer.key
	install := renderInstall(t, values)

	upgradedIssuer := generateIssuerCerts(t, true)
	defer upgradedIssuer.cleanup()

	upgradeOpts.identityOptions.trustPEMFile = upgradedIssuer.caFile
	upgradeOpts.identityOptions.crtPEMFile = upgradedIssuer.crtFile
	upgradeOpts.identityOptions.keyPEMFile = upgradedIssuer.keyFile

	_, err := renderUpgrade(install.String()+externalIssuerSecret(issuer), upgradeOpts, nil, false)

	expectedErr := "cannot update issuer certificates if you are using external cert management solution"

	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error: %s but got %s", expectedErr, err)
	}
}

func TestUpgradeOverwriteIssuer(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	issuerCerts := generateIssuerCerts(t, true)
	defer issuerCerts.cleanup()

	upgradeOpts.identityOptions.trustPEMFile = issuerCerts.caFile
	upgradeOpts.identityOptions.crtPEMFile = issuerCerts.crtFile
	upgradeOpts.identityOptions.keyPEMFile = issuerCerts.keyFile
	install, upgrade, err := renderInstallAndUpgrade(t, installOpts, upgradeOpts)
	if err != nil {
		t.Fatal(err)
	}
	// When upgrading the trust root, we expect to see the new trust root passed
	// to each proxy, the trust root updated in the linkerd-config, and the
	// updated credentials in the linkerd-identity-issuer secret.
	expected := replaceVersions(install.String())
	expectedManifests := parseManifestList(expected)
	upgradeManifests := parseManifestList(upgrade.String())
	for id, diffs := range diffManifestLists(expectedManifests, upgradeManifests) {
		for _, diff := range diffs {
			if ignorableDiff(id, diff) {
				continue
			}
			if isProxyEnvDiff(diff.path) {
				continue
			}
			if id == "ConfigMap/linkerd-config" {
				continue
			}
			if id == "Secret/linkerd-identity-issuer" {
				if pathMatch(diff.path, []string{"data", "crt.pem"}) {
					if diff.b.(string) != issuerCerts.crt {
						diff.a = issuerCerts.crt
						t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
					}
				} else if pathMatch(diff.path, []string{"data", "key.pem"}) {
					if diff.b.(string) != issuerCerts.key {
						diff.a = issuerCerts.key
						t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
					}
				} else if pathMatch(diff.path, []string{"metadata", "annotations", "linkerd.io/identity-issuer-expiry"}) {
					// Differences in expiry are expected; do nothing.
				} else {
					t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
				}
				continue
			}
			t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
		}
	}
}

func TestUpgradeFailsWithOnlyIssuerCert(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	issuerCerts := generateIssuerCerts(t, true)
	defer issuerCerts.cleanup()
	upgradeOpts.identityOptions.trustPEMFile = issuerCerts.caFile
	upgradeOpts.identityOptions.crtPEMFile = issuerCerts.crtFile
	_, _, err := renderInstallAndUpgrade(t, installOpts, upgradeOpts)

	expectedErr := "a private key file must be specified if other credentials are provided"

	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error: %s but got %s", expectedErr, err)
	}
}

func TestUpgradeFailsWithOnlyIssuerKey(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	issuerCerts := generateIssuerCerts(t, true)
	defer issuerCerts.cleanup()
	upgradeOpts.identityOptions.trustPEMFile = issuerCerts.caFile
	upgradeOpts.identityOptions.keyPEMFile = issuerCerts.keyFile
	_, _, err := renderInstallAndUpgrade(t, installOpts, upgradeOpts)

	expectedErr := "a certificate file must be specified if other credentials are provided"

	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error: %s but got %s", expectedErr, err)
	}
}

func TestUpgradeRootFailsWithOldPods(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	oldIssuer := generateIssuerCerts(t, false)
	defer oldIssuer.cleanup()

	install := renderInstall(t, installValues(t, installOpts, nil))

	issuerCerts := generateIssuerCerts(t, true)
	defer issuerCerts.cleanup()
	upgradeOpts.identityOptions.trustPEMFile = issuerCerts.caFile
	upgradeOpts.identityOptions.keyPEMFile = issuerCerts.keyFile
	upgradeOpts.identityOptions.crtPEMFile = issuerCerts.crtFile
	_, err := renderUpgrade(install.String()+podWithSidecar(oldIssuer), upgradeOpts, nil, false)

	expectedErr := "You are attempting to use an issuer certificate which does not validate against the trust anchors of the following pods"
	if err == nil || !strings.HasPrefix(err.Error(), expectedErr) {
		t.Errorf("Expected error: %s but got %s", expectedErr, err)
	}
}

func TestUpgradeTracingAddon(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	allStageOptions := &allStageOptions{
		addOnConfig: filepath.Join("testdata", "addon_config.yaml"),
	}

	install := renderInstall(t, installValues(t, installOpts, nil))
	upgrade, err := renderUpgrade(install.String(), upgradeOpts, allStageOptions, false)
	if err != nil {
		t.Fatal(err)
	}
	expected := replaceVersions(install.String())
	expectedManifests := parseManifestList(expected)
	upgradeManifests := parseManifestList(upgrade.String())
	diffMap := diffManifestLists(expectedManifests, upgradeManifests)
	tracingManifests := []string{
		"Service/linkerd-jaeger", "Deployment/linkerd-jaeger", "ConfigMap/linkerd-config-addons",
		"ServiceAccount/linkerd-jaeger", "Service/linkerd-collector", "ConfigMap/linkerd-collector-config",
		"ServiceAccount/linkerd-collector", "Deployment/linkerd-collector",
	}
	for _, id := range tracingManifests {
		if _, ok := diffMap[id]; ok {
			delete(diffMap, id)
		} else {
			t.Errorf("Expected %s in upgrade output but was absent", id)
		}
	}
	for id, diffs := range diffMap {
		for _, diff := range diffs {
			if ignorableDiff(id, diff) {
				continue
			}
			if id == "Deployment/linkerd-web" && pathMatch(diff.path, []string{"spec", "template", "spec", "containers", "*", "args"}) {
				continue
			}
			t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
		}
	}
}

func TestUpgradeOverwriteTracingAddon(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	installAllStageOptions := &allStageOptions{
		addOnConfig: filepath.Join("testdata", "addon_config.yaml"),
	}
	upgradeAllStageOptions := &allStageOptions{
		addOnConfig: filepath.Join("testdata", "addon_config_overwrite.yaml"),
	}
	upgradeOpts.traceCollector = "overwrite-collector"
	upgradeOpts.traceCollectorSvcAccount = "overwrite-collector.default"
	installValues := installValues(t, installOpts, installAllStageOptions)
	install := renderInstall(t, installValues)
	upgrade, err := renderUpgrade(install.String(), upgradeOpts, upgradeAllStageOptions, false)
	if err != nil {
		t.Fatal(err)
	}
	expected := replaceVersions(install.String())
	expectedManifests := parseManifestList(expected)
	upgradeManifests := parseManifestList(upgrade.String())
	diffMap := diffManifestLists(expectedManifests, upgradeManifests)
	tracingManifests := []string{
		"ConfigMap/linkerd-config-addons",
		"Service/overwrite-collector", "ConfigMap/overwrite-collector-config",
		"ServiceAccount/overwrite-collector", "Deployment/overwrite-collector",
		"Service/linkerd-collector", "ConfigMap/linkerd-collector-config",
		"ServiceAccount/linkerd-collector", "Deployment/linkerd-collector",
	}
	for _, id := range tracingManifests {
		if _, ok := diffMap[id]; ok {
			delete(diffMap, id)
		} else {
			t.Errorf("Expected %s in upgrade output diff but was absent", id)
		}
	}
	for id, diffs := range diffMap {
		for _, diff := range diffs {
			if ignorableDiff(id, diff) {
				continue
			}
			t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
		}
	}
}

func TestUpgradeTwoLevelWebhookCrts(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	// This tests the case where the webhook certs are not self-signed.
	values := installValues(t, installOpts, nil)
	injectorCerts := generateCerts(t, "linkerd-proxy-injector.linkerd.svc", false)
	defer injectorCerts.cleanup()
	values.ProxyInjector.TLS = &linkerd2.TLS{
		CaBundle: injectorCerts.ca,
		CrtPEM:   injectorCerts.crt,
		KeyPEM:   injectorCerts.key,
	}
	tapCerts := generateCerts(t, "linkerd-tap.linkerd.svc", false)
	defer tapCerts.cleanup()
	values.Tap.TLS = &linkerd2.TLS{
		CaBundle: tapCerts.ca,
		CrtPEM:   tapCerts.crt,
		KeyPEM:   tapCerts.key,
	}
	validatorCerts := generateCerts(t, "linkerd-sp-validator.linkerd.svc", false)
	defer validatorCerts.cleanup()
	values.ProfileValidator.TLS = &linkerd2.TLS{
		CaBundle: validatorCerts.ca,
		CrtPEM:   validatorCerts.crt,
		KeyPEM:   validatorCerts.key,
	}

	install := renderInstall(t, values)
	upgrade, err := renderUpgrade(install.String(), upgradeOpts, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	expected := replaceVersions(install.String())
	expectedManifests := parseManifestList(expected)
	upgradeManifests := parseManifestList(upgrade.String())
	for id, diffs := range diffManifestLists(expectedManifests, upgradeManifests) {
		for _, diff := range diffs {
			if ignorableDiff(id, diff) {
				continue
			}
			t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
		}
	}
}

func TestUpgradeWithAddonDisabled(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	allStageOptions := &allStageOptions{
		addOnConfig: filepath.Join("testdata", "grafana_disabled.yaml"),
	}
	installValues := installValues(t, installOpts, allStageOptions)
	install := renderInstall(t, installValues)
	upgrade, err := renderUpgrade(install.String(), upgradeOpts, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	expected := replaceVersions(install.String())
	expectedManifests := parseManifestList(expected)
	upgradeManifests := parseManifestList(upgrade.String())
	for id, diffs := range diffManifestLists(expectedManifests, upgradeManifests) {
		for _, diff := range diffs {
			if ignorableDiff(id, diff) {
				continue
			}
			t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
		}
	}
}

func TestUpgradeEnableAddon(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	installAllStageOptions := &allStageOptions{
		addOnConfig: filepath.Join("testdata", "grafana_disabled.yaml"),
	}
	upgradeAllStageOptions := &allStageOptions{
		addOnConfig: filepath.Join("testdata", "grafana_enabled.yaml"),
	}

	installValues := installValues(t, installOpts, installAllStageOptions)
	install := renderInstall(t, installValues)
	upgrade, err := renderUpgrade(install.String(), upgradeOpts, upgradeAllStageOptions, false)
	if err != nil {
		t.Fatal(err)
	}
	expected := replaceVersions(install.String())
	expectedManifests := parseManifestList(expected)
	upgradeManifests := parseManifestList(upgrade.String())
	diffMap := diffManifestLists(expectedManifests, upgradeManifests)
	addonManifests := []string{
		"ServiceAccount/linkerd-grafana", "Deployment/linkerd-grafana", "Service/linkerd-grafana",
		"ConfigMap/linkerd-grafana-config", "ConfigMap/linkerd-config-addons",
	}
	for _, id := range addonManifests {
		if _, ok := diffMap[id]; ok {
			delete(diffMap, id)
		} else {
			t.Errorf("Expected %s in upgrade output but was absent", id)
		}
	}
	for id, diffs := range diffMap {
		for _, diff := range diffs {
			if ignorableDiff(id, diff) {
				continue
			}
			if id == "RoleBinding/linkerd-psp" && pathMatch(diff.path, []string{"subjects"}) {
				continue
			}
			if id == "Deployment/linkerd-web" && pathMatch(diff.path, []string{"spec", "template", "spec", "containers", "*", "args"}) {
				continue
			}
			t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
		}
	}
}

func TestUpgradeRemoveAddonKeys(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	installAllStageOptions := &allStageOptions{
		addOnConfig: filepath.Join("testdata", "grafana_enabled_resources.yaml"),
	}
	upgradeAllStageOptions := &allStageOptions{
		addOnConfig: filepath.Join("testdata", "grafana_enabled.yaml"),
	}
	installValues := installValues(t, installOpts, installAllStageOptions)
	install := renderInstall(t, installValues)
	upgrade, err := renderUpgrade(install.String(), upgradeOpts, upgradeAllStageOptions, false)
	if err != nil {
		t.Fatal(err)
	}
	expected := replaceVersions(install.String())
	expectedManifests := parseManifestList(expected)
	upgradeManifests := parseManifestList(upgrade.String())
	for id, diffs := range diffManifestLists(expectedManifests, upgradeManifests) {
		for _, diff := range diffs {
			if ignorableDiff(id, diff) {
				continue
			}
			t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
		}
	}
}

func TestUpgradeOverwriteRemoveAddonKeys(t *testing.T) {
	installOpts, upgradeOpts := testOptions(t)

	installAllStageOptions := &allStageOptions{
		addOnConfig: filepath.Join("testdata", "grafana_enabled_resources.yaml"),
	}
	upgradeAllStageOptions := &allStageOptions{
		addOnConfig: filepath.Join("testdata", "grafana_enabled.yaml"),
	}

	installValues := installValues(t, installOpts, installAllStageOptions)
	install := renderInstall(t, installValues)

	upgrade, err := renderUpgrade(install.String(), upgradeOpts, upgradeAllStageOptions, true)
	if err != nil {
		t.Fatal(err)
	}
	expected := replaceVersions(install.String())
	expectedManifests := parseManifestList(expected)
	upgradeManifests := parseManifestList(upgrade.String())
	diffMap := diffManifestLists(expectedManifests, upgradeManifests)
	if _, ok := diffMap["ConfigMap/linkerd-config-addons"]; ok {
		delete(diffMap, "ConfigMap/linkerd-config-addons")
	} else {
		t.Error("Expected ConfigMap/linkerd-config-addons in upgrade output diff but was absent")
	}
	for id, diffs := range diffMap {
		for _, diff := range diffs {
			if ignorableDiff(id, diff) {
				continue
			}
			if id == "Deployment/linkerd-grafana" && pathMatch(diff.path, []string{"spec", "template", "spec", "containers", "*", "resources"}) {
				continue
			}
			t.Errorf("Unexpected diff in %s:\n%s", id, diff.String())
		}
	}
}

/* Helpers */

func testUpgradeOptions() (*installUpgradeOptions, error) {
	defaults, err := charts.NewValues(false)
	if err != nil {
		return nil, err
	}
	_, o, err := makeInstallUpgradeFlags(defaults)
	if err != nil {
		return nil, err
	}

	o.controlPlaneVersion = upgradeControlPlaneVersion
	o.proxyVersion = upgradeProxyVersion
	o.debugImageVersion = upgradeDebugVersion
	return o, nil
}

func testOptions(t *testing.T) (*installUpgradeOptions, *installUpgradeOptions) {
	installOpts, err := testInstallOptions()
	if err != nil {
		t.Fatalf("failed to create install options: %s", err)
	}
	upgradeOpts, err := testUpgradeOptions()
	if err != nil {
		t.Fatalf("failed to create upgrade options: %s", err)
	}
	return installOpts, upgradeOpts
}

func replaceVersions(manifest string) string {
	manifest = strings.ReplaceAll(manifest, installProxyVersion, upgradeProxyVersion)
	manifest = strings.ReplaceAll(manifest, installControlPlaneVersion, upgradeControlPlaneVersion)
	manifest = strings.ReplaceAll(manifest, installDebugVersion, upgradeDebugVersion)
	return manifest
}

func generateIssuerCerts(t *testing.T, b64encode bool) issuerCerts {
	return generateCerts(t, "identity.linkerd.cluster.local", b64encode)
}

func generateCerts(t *testing.T, name string, b64encode bool) issuerCerts {
	ca, err := tls.GenerateRootCAWithDefaults("test")
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ca.GenerateCA(name, -1)
	if err != nil {
		t.Fatal(err)
	}
	caPem := strings.TrimSpace(issuer.Cred.EncodePEM())
	keyPem := strings.TrimSpace(issuer.Cred.EncodePrivateKeyPEM())
	crtPem := strings.TrimSpace(issuer.Cred.EncodeCertificatePEM())

	caFile, err := ioutil.TempFile("", "ca.*.pem")
	if err != nil {
		t.Fatal(err)
	}
	crtFile, err := ioutil.TempFile("", "crt.*.pem")
	if err != nil {
		t.Fatal(err)
	}
	keyFile, err := ioutil.TempFile("", "key.*.pem")
	if err != nil {
		t.Fatal(err)
	}

	_, err = caFile.Write([]byte(caPem))
	if err != nil {
		t.Fatal(err)
	}
	_, err = crtFile.Write([]byte(crtPem))
	if err != nil {
		t.Fatal(err)
	}
	_, err = keyFile.Write([]byte(keyPem))
	if err != nil {
		t.Fatal(err)
	}

	if b64encode {
		caPem = base64.StdEncoding.EncodeToString([]byte(caPem))
		crtPem = base64.StdEncoding.EncodeToString([]byte(crtPem))
		keyPem = base64.StdEncoding.EncodeToString([]byte(keyPem))
	}

	return issuerCerts{
		caFile:  caFile.Name(),
		ca:      caPem,
		crtFile: crtFile.Name(),
		crt:     crtPem,
		keyFile: keyFile.Name(),
		key:     keyPem,
	}
}

func (ic issuerCerts) cleanup() {
	os.Remove(ic.caFile)
	os.Remove(ic.crtFile)
	os.Remove(ic.keyFile)
}

func externalIssuerSecret(certs issuerCerts) string {
	return fmt.Sprintf(`---
apiVersion: v1
kind: Secret
metadata:
  name: linkerd-identity-issuer
  namespace: linkerd
data:
  tls.crt: %s
  tls.key: %s
  ca.crt: %s
type: kubernetes.io/tls
`, certs.crt, certs.key, certs.ca)
}

func indentLines(s string, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func podWithSidecar(certs issuerCerts) string {
	return fmt.Sprintf(`---
apiVersion: v1
kind: Pod
metadata:
  annotations:
    linkerd.io/created-by: linkerd/cli some-version
    linkerd.io/identity-mode: default
    linkerd.io/proxy-version: some-version
  labels:
    linkerd.io/control-plane-ns: linkerd
  name: backend-wrong-anchors
  namespace: some-namespace
spec:
  containers:
  - env:
    - name: LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS
      value: |
%s
    image: gcr.io/linkerd-io/proxy:some-version
    name: linkerd-proxy
`, indentLines(certs.ca, "        "))
}

func isProxyEnvDiff(path []string) bool {
	template := []string{"spec", "template", "spec", "containers", "*", "env", "*", "value"}
	return pathMatch(path, template)
}

func pathMatch(path []string, template []string) bool {
	if len(path) != len(template) {
		return false
	}
	for i, elem := range template {
		if elem != "*" && elem != path[i] {
			return false
		}
	}
	return true
}

func installValues(t *testing.T, installOpts *installUpgradeOptions, allStageOptions *allStageOptions) *linkerd2.Values {

	installValues, err := linkerd2.NewValues(false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = installOpts.applyToValues(nil, installValues)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if allStageOptions != nil {
		err = allStageOptions.overrideValues(installValues)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
	return installValues
}

func renderInstall(t *testing.T, values *linkerd2.Values) bytes.Buffer {
	var installBuf bytes.Buffer
	if err := render(&installBuf, values, ""); err != nil {
		t.Fatalf("could not render install manifests: %s", err)
	}
	return installBuf
}

func renderUpgrade(installManifest string, upgradeOpts *installUpgradeOptions, allStageOptions *allStageOptions, addonOverride bool) (bytes.Buffer, error) {
	err := upgradeOpts.validate()
	if err != nil {
		return bytes.Buffer{}, err
	}
	k, err := k8s.NewFakeAPIFromManifests([]io.Reader{strings.NewReader(installManifest)})
	if err != nil {
		return bytes.Buffer{}, err
	}

	upgradeOverrides, err := upgradeOpts.toOverrides(k)
	if err != nil {
		return bytes.Buffer{}, err
	}
	if allStageOptions != nil {
		allStageOverrides, err := allStageOptions.toOverrides()
		if err != nil {
			return bytes.Buffer{}, err
		}

		fmt.Println("All stage overrides")
		fmt.Println(allStageOverrides.String())

		err = upgradeOverrides.Merge(allStageOverrides)
		if err != nil {
			return bytes.Buffer{}, err
		}

		fmt.Println("merged overrides")
		fmt.Println(upgradeOverrides.String())
	}

	options := upgradeOptions{
		addOnOverwrite: addonOverride,
	}
	return upgrade(k, &options, upgradeOverrides, "")
}

func renderInstallAndUpgrade(t *testing.T, installOpts *installUpgradeOptions, upgradeOpts *installUpgradeOptions) (bytes.Buffer, bytes.Buffer, error) {
	err := installOpts.validate()
	if err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, err
	}
	installBuf := renderInstall(t, installValues(t, installOpts, nil))
	upgradeBuf, err := renderUpgrade(installBuf.String(), upgradeOpts, nil, false)
	return installBuf, upgradeBuf, err
}

// Certain resources are expected to change during an upgrade. We can safely
// ignore these diffs in every test.
func ignorableDiff(id string, diff diff) bool {
	if id == "Secret/linkerd-config-overrides" {
		// The config overrides will always change because at least the control
		// plane and proxy versions will change.
		return true
	}
	if id == "ConfigMap/linkerd-config" {
		// The upgrade process destroys the contents of the linkerd-config
		// which will no longer be used.  This is a temporary state of afairs
		// and the linkerd-config configmap will be deleted from the install
		// chart soon.
		return true
	}
	if (strings.HasPrefix(id, "MutatingWebhookConfiguration") || strings.HasPrefix(id, "ValidatingWebhookConfiguration")) &&
		pathMatch(diff.path, []string{"webhooks", "*", "clientConfig", "caBundle"}) {
		// Webhook TLS chains are regenerated upon upgrade so we expect the
		// caBundle to change.
		return true
	}
	if strings.HasPrefix(id, "APIService") &&
		pathMatch(diff.path, []string{"spec", "caBundle"}) {
		// APIService TLS chains are regenerated upon upgrade so we expect the
		// caBundle to change.
		return true
	}
	if id == "Secret/linkerd-proxy-injector-tls" || id == "Secret/linkerd-sp-validator-tls" || id == "Secret/linkerd-tap-tls" {
		// Webhook and APIService TLS chains are regenerated upon upgrade.
		return true
	}
	return false
}
