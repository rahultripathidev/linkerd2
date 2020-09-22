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

	"github.com/linkerd/linkerd2/cli/flag"
	"github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	charts "github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/tls"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
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
	installOpts, upgradeOpts, _ := testOptions(t)
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
	installOpts, upgradeOpts, _ := testOptions(t)
	installOpts.Global.HighAvailability = true
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
	installOpts, upgradeOpts, _ := testOptions(t)

	issuer := generateIssuerCerts(t, true)
	defer issuer.cleanup()

	installOpts.Identity = &linkerd2.Identity{
		Issuer: &linkerd2.Issuer{
			Scheme: string(corev1.SecretTypeTLS),
			TLS: &linkerd2.IssuerTLS{
				CrtPEM: issuer.crt,
				KeyPEM: issuer.key,
			},
		},
	}
	installOpts.Global.IdentityTrustAnchorsPEM = issuer.ca
	install := renderInstall(t, installOpts)
	upgrade, err := renderUpgrade(install.String()+externalIssuerSecret(issuer), upgradeOpts, false)

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
	installOpts, upgradeOpts, flagSet := testOptions(t)

	issuer := generateIssuerCerts(t, false)
	defer issuer.cleanup()

	installOpts.Global.IdentityTrustDomain = "cluster.local"
	installOpts.Global.IdentityTrustDomain = issuer.ca
	installOpts.Identity.Issuer.Scheme = string(corev1.SecretTypeTLS)
	installOpts.Identity.Issuer.TLS.CrtPEM = issuer.crt
	installOpts.Identity.Issuer.TLS.KeyPEM = issuer.key
	install := renderInstall(t, installOpts)

	upgradedIssuer := generateIssuerCerts(t, true)
	defer upgradedIssuer.cleanup()

	flagSet.Set("identity-trust-anchors-file", upgradedIssuer.caFile)
	flagSet.Set("identity-issuer-certificate-file", upgradedIssuer.crtFile)
	flagSet.Set("identity-issuer-key-file", upgradedIssuer.keyFile)

	_, err := renderUpgrade(install.String()+externalIssuerSecret(issuer), upgradeOpts, false)

	expectedErr := "cannot update issuer certificates if you are using external cert management solution"

	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error: %s but got %s", expectedErr, err)
	}
}

func TestUpgradeOverwriteIssuer(t *testing.T) {
	installOpts, upgradeOpts, flagSet := testOptions(t)

	issuerCerts := generateIssuerCerts(t, false)
	defer issuerCerts.cleanup()

	flagSet.Set("identity-trust-anchors-file", issuerCerts.caFile)
	flagSet.Set("identity-issuer-certificate-file", issuerCerts.crtFile)
	flagSet.Set("identity-issuer-key-file", issuerCerts.keyFile)

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
	installOpts, upgradeOpts, flagSet := testOptions(t)

	issuerCerts := generateIssuerCerts(t, true)
	defer issuerCerts.cleanup()

	flagSet.Set("identity-trust-anchors-file", issuerCerts.caFile)
	flagSet.Set("identity-issuer-certificate-file", issuerCerts.crtFile)

	_, _, err := renderInstallAndUpgrade(t, installOpts, upgradeOpts)

	expectedErr := "a private key file must be specified if other credentials are provided"

	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error: %s but got %s", expectedErr, err)
	}
}

func TestUpgradeFailsWithOnlyIssuerKey(t *testing.T) {
	installOpts, upgradeOpts, flagSet := testOptions(t)

	issuerCerts := generateIssuerCerts(t, false)
	defer issuerCerts.cleanup()

	flagSet.Set("identity-trust-anchors-file", issuerCerts.caFile)
	flagSet.Set("identity-issuer-certificate-file", issuerCerts.crtFile)

	_, _, err := renderInstallAndUpgrade(t, installOpts, upgradeOpts)

	expectedErr := "a certificate file must be specified if other credentials are provided"

	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error: %s but got %s", expectedErr, err)
	}
}

func TestUpgradeRootFailsWithOldPods(t *testing.T) {
	installOpts, upgradeOpts, flagSet := testOptions(t)

	oldIssuer := generateIssuerCerts(t, false)
	defer oldIssuer.cleanup()

	install := renderInstall(t, installOpts)

	issuerCerts := generateIssuerCerts(t, true)
	defer issuerCerts.cleanup()

	flagSet.Set("identity-trust-anchors-file", issuerCerts.caFile)
	flagSet.Set("identity-issuer-certificate-file", issuerCerts.crtFile)
	flagSet.Set("identity-issuer-key-file", issuerCerts.keyFile)

	_, err := renderUpgrade(install.String()+podWithSidecar(oldIssuer), upgradeOpts, false)

	expectedErr := "You are attempting to use an issuer certificate which does not validate against the trust anchors of the following pods"
	if err == nil || !strings.HasPrefix(err.Error(), expectedErr) {
		t.Errorf("Expected error: %s but got %s", expectedErr, err)
	}
}

func TestUpgradeTracingAddon(t *testing.T) {
	installOpts, upgradeOpts, flagSet := testOptions(t)

	install := renderInstall(t, installOpts)

	flagSet.Set("addon-config", filepath.Join("testdata", "addon_config.yaml"))

	upgrade, err := renderUpgrade(install.String(), upgradeOpts, false)
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
	installOpts, upgradeOpts, flagSet := testOptions(t)

	installAddons, err := ioutil.ReadFile(filepath.Join("testdata", "addon_config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	err = yaml.Unmarshal(installAddons, installOpts)
	if err != nil {
		t.Fatal(err)
	}

	install := renderInstall(t, installOpts)

	flagSet.Set("addon-config", filepath.Join("testdata", "addon_config.yaml"))
	flagSet.Set("trace-collector", "overwrite-collector")
	flagSet.Set("trace-collector-svc-account", "overwrite-collector.default")

	upgrade, err := renderUpgrade(install.String(), upgradeOpts, false)
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
	installOpts, upgradeOpts, _ := testOptions(t)

	// This tests the case where the webhook certs are not self-signed.
	injectorCerts := generateCerts(t, "linkerd-proxy-injector.linkerd.svc", false)
	defer injectorCerts.cleanup()
	installOpts.ProxyInjector.TLS = &linkerd2.TLS{
		CaBundle: injectorCerts.ca,
		CrtPEM:   injectorCerts.crt,
		KeyPEM:   injectorCerts.key,
	}
	tapCerts := generateCerts(t, "linkerd-tap.linkerd.svc", false)
	defer tapCerts.cleanup()
	installOpts.Tap.TLS = &linkerd2.TLS{
		CaBundle: tapCerts.ca,
		CrtPEM:   tapCerts.crt,
		KeyPEM:   tapCerts.key,
	}
	validatorCerts := generateCerts(t, "linkerd-sp-validator.linkerd.svc", false)
	defer validatorCerts.cleanup()
	installOpts.ProfileValidator.TLS = &linkerd2.TLS{
		CaBundle: validatorCerts.ca,
		CrtPEM:   validatorCerts.crt,
		KeyPEM:   validatorCerts.key,
	}

	install := renderInstall(t, installOpts)
	upgrade, err := renderUpgrade(install.String(), upgradeOpts, false)
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
	installOpts, upgradeOpts, _ := testOptions(t)

	installAddons, err := ioutil.ReadFile(filepath.Join("testdata", "grafana_disabled.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	err = yaml.Unmarshal(installAddons, installOpts)
	if err != nil {
		t.Fatal(err)
	}

	install := renderInstall(t, installOpts)
	upgrade, err := renderUpgrade(install.String(), upgradeOpts, false)
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
	installOpts, upgradeOpts, flagSet := testOptions(t)

	installAddons, err := ioutil.ReadFile(filepath.Join("testdata", "grafana_disabled.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	err = yaml.Unmarshal(installAddons, installOpts)
	if err != nil {
		t.Fatal(err)
	}

	install := renderInstall(t, installOpts)

	flagSet.Set("addon-config", filepath.Join("testdata", "grafana_enabled.yaml"))

	upgrade, err := renderUpgrade(install.String(), upgradeOpts, false)
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
	installOpts, upgradeOpts, flagSet := testOptions(t)

	installAddons, err := ioutil.ReadFile(filepath.Join("testdata", "grafana_enabled_resources.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	err = yaml.Unmarshal(installAddons, installOpts)
	if err != nil {
		t.Fatal(err)
	}

	install := renderInstall(t, installOpts)

	flagSet.Set("addon-config", filepath.Join("testdata", "grafana_enabled.yaml"))

	upgrade, err := renderUpgrade(install.String(), upgradeOpts, false)
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
	installOpts, upgradeOpts, flagSet := testOptions(t)

	installAddons, err := ioutil.ReadFile(filepath.Join("testdata", "grafana_enabled_resources.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	err = yaml.Unmarshal(installAddons, installOpts)
	if err != nil {
		t.Fatal(err)
	}

	install := renderInstall(t, installOpts)

	flagSet.Set("addon-config", filepath.Join("testdata", "grafana_enabled.yaml"))

	upgrade, err := renderUpgrade(install.String(), upgradeOpts, true)
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

func testUpgradeOptions() ([]flag.Flag, *pflag.FlagSet, error) {
	defaults, err := charts.NewValues(false)
	if err != nil {
		return nil, nil, err
	}

	allStageFlags, allStageFlagSet := makeAllStageFlags(defaults)
	upgradeFlags, upgradeFlagSet, err := makeInstallUpgradeFlags(defaults)
	if err != nil {
		return nil, nil, err
	}
	proxyFlags, proxyFlagSet := makeProxyFlags(defaults)

	flags := flattenFlags(allStageFlags, upgradeFlags, proxyFlags)
	flagSet := pflag.NewFlagSet("upgrade", pflag.ExitOnError)
	flagSet.AddFlagSet(allStageFlagSet)
	flagSet.AddFlagSet(upgradeFlagSet)
	flagSet.AddFlagSet(proxyFlagSet)

	flagSet.Set("control-plane-version", upgradeControlPlaneVersion)
	flagSet.Set("proxy-version", upgradeProxyVersion)

	return flags, flagSet, nil
}

func testOptions(t *testing.T) (*charts.Values, []flag.Flag, *pflag.FlagSet) {
	installValues, err := testInstallOptions()
	if err != nil {
		t.Fatalf("failed to create install options: %s", err)
	}
	upgradeFlags, upgradeFlagSet, err := testUpgradeOptions()
	if err != nil {
		t.Fatalf("failed to create upgrade options: %s", err)
	}
	return installValues, upgradeFlags, upgradeFlagSet
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

func renderInstall(t *testing.T, values *linkerd2.Values) bytes.Buffer {
	var installBuf bytes.Buffer
	if err := render(&installBuf, values, ""); err != nil {
		t.Fatalf("could not render install manifests: %s", err)
	}
	return installBuf
}

func renderUpgrade(installManifest string, upgradeOpts []flag.Flag, addonOverride bool) (bytes.Buffer, error) {
	k, err := k8s.NewFakeAPIFromManifests([]io.Reader{strings.NewReader(installManifest)})
	if err != nil {
		return bytes.Buffer{}, err
	}

	options := upgradeOptions{
		addOnOverwrite: addonOverride,
	}
	return upgrade(k, &options, upgradeOpts, "")
}

func renderInstallAndUpgrade(t *testing.T, installOpts *charts.Values, upgradeOpts []flag.Flag) (bytes.Buffer, bytes.Buffer, error) {
	err := validateValues(nil, installOpts)
	if err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, err
	}
	installBuf := renderInstall(t, installOpts)
	upgradeBuf, err := renderUpgrade(installBuf.String(), upgradeOpts, false)
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
