package cmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/linkerd/linkerd2/cli/flag"
	charts "github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	"github.com/linkerd/linkerd2/pkg/tls"
	corev1 "k8s.io/api/core/v1"
)

const (
	installProxyVersion        = "install-proxy-version"
	installControlPlaneVersion = "install-control-plane-version"
	installDebugVersion        = "install-debug-version"
)

func TestRender(t *testing.T) {
	defaultValues, err := charts.NewValues(false)
	addFakeTLSSecrets(defaultValues)

	// A configuration that shows that all config setting strings are honored
	// by `render()`.
	metaValues := &charts.Values{
		ControllerImage:             "ControllerImage",
		WebImage:                    "WebImage",
		ControllerUID:               2103,
		EnableH2Upgrade:             true,
		WebhookFailurePolicy:        "WebhookFailurePolicy",
		OmitWebhookSideEffects:      false,
		RestrictDashboardPrivileges: false,
		InstallNamespace:            true,
		Identity:                    defaultValues.Identity,
		NodeSelector:                defaultValues.NodeSelector,
		Tolerations:                 defaultValues.Tolerations,
		Global: &charts.Global{
			Namespace:                "Namespace",
			ClusterDomain:            "cluster.local",
			ImagePullPolicy:          "ImagePullPolicy",
			CliVersion:               "CliVersion",
			ControllerComponentLabel: "ControllerComponentLabel",
			ControllerLogLevel:       "ControllerLogLevel",
			ControllerImageVersion:   "ControllerImageVersion",
			ControllerNamespaceLabel: "ControllerNamespaceLabel",
			WorkloadNamespaceLabel:   "WorkloadNamespaceLabel",
			CreatedByAnnotation:      "CreatedByAnnotation",
			ProxyInjectAnnotation:    "ProxyInjectAnnotation",
			ProxyInjectDisabled:      "ProxyInjectDisabled",
			LinkerdNamespaceLabel:    "LinkerdNamespaceLabel",
			ProxyContainerName:       "ProxyContainerName",
			CNIEnabled:               false,
			IdentityTrustDomain:      defaultValues.Global.IdentityTrustDomain,
			IdentityTrustAnchorsPEM:  defaultValues.Global.IdentityTrustAnchorsPEM,
			Proxy: &charts.Proxy{
				DestinationGetNetworks: "DestinationGetNetworks",
				Image: &charts.Image{
					Name:       "ProxyImageName",
					PullPolicy: "ImagePullPolicy",
					Version:    "ProxyVersion",
				},
				LogLevel:  "warn,linkerd=info",
				LogFormat: "plain",
				Ports: &charts.Ports{
					Admin:    4191,
					Control:  4190,
					Inbound:  4143,
					Outbound: 4140,
				},
				UID:   2102,
				Trace: &charts.Trace{},
			},
			ProxyInit: &charts.ProxyInit{
				Image: &charts.Image{
					Name:       "ProxyInitImageName",
					PullPolicy: "ImagePullPolicy",
					Version:    "ProxyInitVersion",
				},
				Resources: &charts.Resources{
					CPU: charts.Constraints{
						Limit:   "100m",
						Request: "10m",
					},
					Memory: charts.Constraints{
						Limit:   "50Mi",
						Request: "10Mi",
					},
				},
				XTMountPath: &charts.VolumeMountPath{
					MountPath: "/run",
					Name:      "linkerd-proxy-init-xtables-lock",
				},
			},
		},
		Configs: charts.ConfigJSONs{
			Global:  "GlobalConfig",
			Proxy:   "ProxyConfig",
			Install: "InstallConfig",
		},
		ControllerReplicas: 1,
		ProxyInjector:      defaultValues.ProxyInjector,
		ProfileValidator:   defaultValues.ProfileValidator,
		Tap:                defaultValues.Tap,
		Dashboard: &charts.Dashboard{
			Replicas: 1,
		},
		Prometheus: charts.Prometheus{
			"enabled": true,
			"image":   "PrometheusImage",
		},
		Tracing: map[string]interface{}{
			"enabled": false,
		},
		Grafana: defaultValues.Grafana,
	}

	haValues, err := charts.NewValues(true)
	if err != nil {
		t.Fatalf("Unexpected error: %v\n", err)
	}
	addFakeTLSSecrets(haValues)

	haWithOverridesValues, err := charts.NewValues(true)
	if err != nil {
		t.Fatalf("Unexpected error: %v\n", err)
	}

	haWithOverridesValues.Global.HighAvailability = true
	haWithOverridesValues.ControllerReplicas = 2
	haWithOverridesValues.Global.Proxy.Resources.CPU.Request = "400m"
	haWithOverridesValues.Global.Proxy.Resources.Memory.Request = "300Mi"
	addFakeTLSSecrets(haWithOverridesValues)

	cniEnabledValues, err := charts.NewValues(false)
	if err != nil {
		t.Fatalf("Unexpected error: %v\n", err)
	}

	cniEnabledValues.Global.CNIEnabled = true
	addFakeTLSSecrets(cniEnabledValues)

	withProxyIgnoresValues, err := charts.NewValues(false)
	if err != nil {
		t.Fatalf("Unexpected error: %v\n", err)
	}
	withProxyIgnoresValues.Global.ProxyInit.IgnoreInboundPorts = "22,8100-8102"
	withProxyIgnoresValues.Global.ProxyInit.IgnoreOutboundPorts = "5432"
	addFakeTLSSecrets(withProxyIgnoresValues)

	withHeartBeatDisabledValues, err := charts.NewValues(false)
	if err != nil {
		t.Fatalf("Unexpected error: %v\n", err)
	}
	withHeartBeatDisabledValues.DisableHeartBeat = true
	addFakeTLSSecrets(withHeartBeatDisabledValues)

	withRestrictedDashboardPrivilegesValues, err := charts.NewValues(false)
	if err != nil {
		t.Fatalf("Unexpected error: %v\n", err)
	}
	withRestrictedDashboardPrivilegesValues.RestrictDashboardPrivileges = true
	addFakeTLSSecrets(withRestrictedDashboardPrivilegesValues)

	withControlPlaneTracingValues, err := charts.NewValues(false)
	if err != nil {
		t.Fatalf("Unexpected error: %v\n", err)
	}
	withControlPlaneTracingValues.Global.ControlPlaneTracing = true
	addFakeTLSSecrets(withControlPlaneTracingValues)

	customRegistryOverride := "my.custom.registry/linkerd-io"
	withCustomRegistryValues, err := charts.NewValues(false)
	if err != nil {
		t.Fatalf("Unexpected error: %v\n", err)
	}
	flags, flagSet, err := makeInstallUpgradeFlags(withCustomRegistryValues)
	if err != nil {
		t.Fatalf("Unexpected error: %v\n", err)
	}
	flagSet.Set("docker-registry", customRegistryOverride)
	err = flag.ApplySetFlags(withCustomRegistryValues, flags)
	if err != nil {
		t.Fatalf("Unexpected error: %v\n", err)
	}
	addFakeTLSSecrets(withCustomRegistryValues)

	withAddOnValues, err := charts.NewValues(false)
	withAddOnValues.Tracing["enabled"] = true
	addFakeTLSSecrets(withAddOnValues)

	withCustomDestinationGetNetsValues, err := charts.NewValues(false)
	if err != nil {
		t.Fatalf("Unexpected error: %v\n", err)
	}
	withCustomDestinationGetNetsValues.Global.Proxy.DestinationGetNetworks = "10.0.0.0/8,172.0.0.0/8"
	addFakeTLSSecrets(withCustomDestinationGetNetsValues)

	testCases := []struct {
		values         *charts.Values
		goldenFileName string
	}{
		{defaultValues, "install_default.golden"},
		{metaValues, "install_output.golden"},
		{haValues, "install_ha_output.golden"},
		{haWithOverridesValues, "install_ha_with_overrides_output.golden"},
		{cniEnabledValues, "install_no_init_container.golden"},
		{withProxyIgnoresValues, "install_proxy_ignores.golden"},
		{withHeartBeatDisabledValues, "install_heartbeat_disabled_output.golden"},
		{withRestrictedDashboardPrivilegesValues, "install_restricted_dashboard.golden"},
		{withControlPlaneTracingValues, "install_controlplane_tracing_output.golden"},
		{withCustomRegistryValues, "install_custom_registry.golden"},
		{withAddOnValues, "install_addon.golden"},
		{withCustomDestinationGetNetsValues, "install_default_override_dst_get_nets.golden"},
	}

	for i, tc := range testCases {
		tc := tc // pin
		t.Run(fmt.Sprintf("%d: %s", i, tc.goldenFileName), func(t *testing.T) {
			var buf bytes.Buffer
			if err := render(&buf, tc.values, ""); err != nil {
				t.Fatalf("Failed to render templates: %v", err)
			}
			diffTestdata(t, tc.goldenFileName, buf.String())
		})
	}
}

func TestValidateAndBuild_Errors(t *testing.T) {
	t.Run("Fails validation for invalid ignoreInboundPorts", func(t *testing.T) {
		values, err := testInstallOptions()
		if err != nil {
			t.Fatalf("Unexpected error: %v\n", err)
		}
		values.Global.ProxyInit.IgnoreInboundPorts = "-25"
		err = validateValues(nil, values)
		if err == nil {
			t.Fatal("expected error but got nothing")
		}
	})

	t.Run("Fails validation for invalid ignoreOutboundPorts", func(t *testing.T) {
		values, err := testInstallOptions()
		if err != nil {
			t.Fatalf("Unexpected error: %v\n", err)
		}
		values.Global.ProxyInit.IgnoreOutboundPorts = "-25"
		err = validateValues(nil, values)
		if err == nil {
			t.Fatal("expected error but got nothing")
		}
	})
}

func testInstallOptions() (*charts.Values, error) {
	values, err := charts.NewValues(false)
	if err != nil {
		return nil, err
	}

	values.Global.Proxy.Image.Version = installProxyVersion
	values.DebugContainer.Image.Version = installDebugVersion
	values.ControllerImageVersion = installControlPlaneVersion
	values.Global.ControllerImageVersion = installControlPlaneVersion
	values.HeartbeatSchedule = fakeHeartbeatSchedule()

	data, err := ioutil.ReadFile(filepath.Join("testdata", "valid-crt.pem"))
	if err != nil {
		return nil, err
	}

	crt, err := tls.DecodePEMCrt(string(data))
	if err != nil {
		return nil, err
	}
	values.Identity.Issuer.TLS.CrtPEM = crt.EncodeCertificatePEM()
	values.Identity.Issuer.CrtExpiry = crt.Certificate.NotAfter

	key, err := loadKeyPEM(filepath.Join("testdata", "valid-key.pem"))
	if err != nil {
		return nil, err
	}
	values.Identity.Issuer.TLS.KeyPEM = key

	data, err = ioutil.ReadFile(filepath.Join("testdata", "valid-trust-anchors.pem"))
	if err != nil {
		return nil, err
	}
	values.Global.IdentityTrustAnchorsPEM = string(data)

	return values, nil
}

func TestValidate(t *testing.T) {
	t.Run("Accepts the default options as valid", func(t *testing.T) {
		values, err := testInstallOptions()
		if err != nil {
			t.Fatalf("Unexpected error: %v\n", err)
		}

		if err := validateValues(nil, values); err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
	})

	t.Run("Rejects invalid destination networks", func(t *testing.T) {
		values, err := testInstallOptions()
		if err != nil {
			t.Fatalf("Unexpected error: %v\n", err)
		}

		values.Global.Proxy.DestinationGetNetworks = "wrong"
		expected := "cannot parse destination get networks: invalid CIDR address: wrong"

		err = validateValues(nil, values)
		if err == nil {
			t.Fatal("Expected error, got nothing")
		}
		if err.Error() != expected {
			t.Fatalf("Expected error string\"%s\", got \"%s\"", expected, err)
		}
	})

	t.Run("Rejects invalid controller log level", func(t *testing.T) {
		values, err := testInstallOptions()
		if err != nil {
			t.Fatalf("Unexpected error: %v\n", err)
		}

		values.Global.ControllerLogLevel = "super"
		expected := "--controller-log-level must be one of: panic, fatal, error, warn, info, debug"

		err = validateValues(nil, values)
		if err == nil {
			t.Fatal("Expected error, got nothing")
		}
		if err.Error() != expected {
			t.Fatalf("Expected error string\"%s\", got \"%s\"", expected, err)
		}
	})

	t.Run("Properly validates proxy log level", func(t *testing.T) {
		testCases := []struct {
			input string
			valid bool
		}{
			{"", false},
			{"info", true},
			{"somemodule", true},
			{"bad%name", false},
			{"linkerd2_proxy=debug", true},
			{"linkerd2%proxy=debug", false},
			{"linkerd2_proxy=foobar", false},
			{"linker2d_proxy,std::option", true},
			{"warn,linkerd=info", true},
			{"warn,linkerd=foobar", false},
		}

		values, err := testInstallOptions()
		if err != nil {
			t.Fatalf("Unexpected error: %v\n", err)
		}

		for _, tc := range testCases {
			values.Global.Proxy.LogLevel = tc.input
			err := validateValues(nil, values)
			if tc.valid && err != nil {
				t.Fatalf("Error not expected: %s", err)
			}
			if !tc.valid && err == nil {
				t.Fatalf("Expected error string \"%s is not a valid proxy log level\", got nothing", tc.input)
			}
			expectedErr := fmt.Sprintf("\"%s\" is not a valid proxy log level - for allowed syntax check https://docs.rs/env_logger/0.6.0/env_logger/#enabling-logging", tc.input)
			if tc.input == "" {
				expectedErr = "--proxy-log-level must not be empty"
			}
			if !tc.valid && err.Error() != expectedErr {
				t.Fatalf("Expected error string \"%s\", got \"%s\"; input=\"%s\"", expectedErr, err, tc.input)
			}
		}
	})

	t.Run("Validates the issuer certs upon install", func(t *testing.T) {

		testCases := []struct {
			crtFilePrefix string
			expectedError string
		}{
			{"valid", ""},
			{"expired", "failed to verify issuer certs stored on disk: not valid anymore. Expired on 1990-01-01T01:01:11Z"},
			{"not-valid-yet", "failed to verify issuer certs stored on disk: not valid before: 2100-01-01T01:00:51Z"},
			{"wrong-domain", "failed to verify issuer certs stored on disk: x509: certificate is valid for wrong.linkerd.cluster.local, not identity.linkerd.cluster.local"},
			{"wrong-algo", "failed to verify issuer certs stored on disk: must use P-256 curve for public key, instead P-521 was used"},
		}
		for _, tc := range testCases {

			values, err := testInstallOptions()
			if err != nil {
				t.Fatalf("Unexpected error: %v\n", err)
			}

			crt, err := loadCrtPEM(filepath.Join("testdata", tc.crtFilePrefix+"-crt.pem"))
			if err != nil {
				t.Fatal(err)
			}
			values.Identity.Issuer.TLS.CrtPEM = crt

			key, err := loadKeyPEM(filepath.Join("testdata", tc.crtFilePrefix+"-key.pem"))
			if err != nil {
				t.Fatal(err)
			}
			values.Identity.Issuer.TLS.KeyPEM = key

			ca, err := ioutil.ReadFile(filepath.Join("testdata", tc.crtFilePrefix+"-trust-anchors.pem"))
			if err != nil {
				t.Fatal(err)
			}
			values.Global.IdentityTrustAnchorsPEM = string(ca)

			err = validateValues(nil, values)

			if tc.expectedError != "" {
				if err == nil {
					t.Fatal("Expected error, got nothing")
				}
				if err.Error() != tc.expectedError {
					t.Fatalf("Expected error string\"%s\", got \"%s\"", tc.expectedError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error bu got \"%s\"", err)
				}
			}
		}
	})

	t.Run("Rejects identity cert files data when external issuer is set", func(t *testing.T) {

		values, err := testInstallOptions()
		if err != nil {
			t.Fatalf("Unexpected error: %v\n", err)
		}

		values.Identity.Issuer.Scheme = string(corev1.SecretTypeTLS)

		withoutCertDataOptions, _ := values.DeepCopy()

		withCrtFile, _ := values.DeepCopy()
		withCrtFile.Identity.Issuer.TLS.CrtPEM = "certificate"

		withTrustAnchorsFile, _ := values.DeepCopy()
		withTrustAnchorsFile.Global.IdentityTrustAnchorsPEM = "trust anchors"

		withKeyFile, _ := values.DeepCopy()
		withKeyFile.Identity.Issuer.TLS.KeyPEM = "key"

		testCases := []struct {
			input         *charts.Values
			expectedError string
		}{
			{withoutCertDataOptions, ""},
			{withCrtFile, "--identity-issuer-certificate-file must not be specified if --identity-external-issuer=true"},
			{withTrustAnchorsFile, "--identity-trust-anchors-file must not be specified if --identity-external-issuer=true"},
			{withKeyFile, "--identity-issuer-key-file must not be specified if --identity-external-issuer=true"},
		}

		for _, tc := range testCases {
			err = validateValues(nil, tc.input)

			if tc.expectedError != "" {
				if err == nil {
					t.Fatal("Expected error, got nothing")
				}
				if err.Error() != tc.expectedError {
					t.Fatalf("Expected error string\"%s\", got \"%s\"", tc.expectedError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error bu got \"%s\"", err)

				}
			}
		}
	})
}

func fakeHeartbeatSchedule() string {
	return "1 2 3 4 5"
}

func addFakeTLSSecrets(values *charts.Values) {
	values.ProxyInjector.CrtPEM = "proxy injector crt"
	values.ProxyInjector.KeyPEM = "proxy injector key"
	values.ProxyInjector.CaBundle = "proxy injector CA bundle"
	values.ProfileValidator.CrtPEM = "profile validator crt"
	values.ProfileValidator.KeyPEM = "profile validator key"
	values.ProfileValidator.CaBundle = "profile validator CA bundle"
	values.Tap.CrtPEM = "tap crt"
	values.Tap.KeyPEM = "tap key"
	values.Tap.CaBundle = "tap CA bundle"
}
