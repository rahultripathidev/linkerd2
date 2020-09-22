package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/linkerd/linkerd2/cli/flag"
	pb "github.com/linkerd/linkerd2/controller/gen/config"
	charts "github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	"github.com/linkerd/linkerd2/pkg/healthcheck"
	"github.com/linkerd/linkerd2/pkg/issuercerts"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/tls"
	"github.com/linkerd/linkerd2/pkg/version"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

func loadStoredValuesLegacy(k *k8s.KubernetesAPI, upgradeOptions *upgradeOptions) (*charts.Values, error) {

	// We fetch the configs directly from kubernetes because we need to be able
	// to upgrade/reinstall the control plane when the API is not available; and
	// this also serves as a passive check that we have privileges to access this
	// control plane.
	_, configs, err := healthcheck.FetchLinkerdConfigMap(k, controlPlaneNamespace)
	if err != nil {
		return nil, fmt.Errorf("could not fetch configs from kubernetes: %s", err)
	}
	repairConfigs(configs)

	values, err := charts.NewValues(false)
	if err != nil {
		return nil, err
	}
	allStageFlags, allStageFlagSet := makeAllStageFlags(values)
	installFlags, installFlagSet := makeInstallFlags(values)
	upgradeFlags, installUpgradeFlagSet, err := makeInstallUpgradeFlags(values)
	if err != nil {
		return nil, err
	}
	proxyFlags, proxyFlagSet := makeProxyFlags(values)

	flagSet := pflag.NewFlagSet("loaded_flags", pflag.ExitOnError)
	flagSet.AddFlagSet(allStageFlagSet)
	flagSet.AddFlagSet(installFlagSet)
	flagSet.AddFlagSet(installUpgradeFlagSet)
	flagSet.AddFlagSet(proxyFlagSet)

	setFlagsFromInstall(flagSet, configs.GetInstall().GetFlags())

	flags := flattenFlags(allStageFlags, installFlags, upgradeFlags, proxyFlags)
	err = flag.ApplySetFlags(values, flags)
	if err != nil {
		return nil, err
	}

	idctx := configs.GetGlobal().GetIdentityContext()
	if idctx.GetTrustDomain() != "" && idctx.GetTrustAnchorsPem() != "" {
		err = fetchIdentityValues(k, upgradeOptions, idctx, values)
		if err != nil {
			return nil, err
		}
	}

	if !upgradeOptions.addOnOverwrite {
		// Update Add-Ons Configuration from the linkerd-value cm
		cmRawValues, _ := k8s.GetAddOnsConfigMap(k, controlPlaneNamespace)
		if cmRawValues != nil {
			//Cm is present now get the data
			cmData, ok := cmRawValues["values"]
			if !ok {
				return nil, fmt.Errorf("values subpath not found in %s configmap", k8s.AddOnsConfigMapName)
			}

			if err = yaml.Unmarshal([]byte(cmData), &values); err != nil {
				return nil, err
			}
		}
	}

	return values, nil
}

func setFlagsFromInstall(flags *pflag.FlagSet, installFlags []*pb.Install_Flag) {
	for _, i := range installFlags {
		if f := flags.Lookup(i.GetName()); f != nil && !f.Changed {
			// The function recordFlags() stores the string representation of flags in the ConfigMap
			// so a stringSlice is stored e.g. as [a,b].
			// To avoid having f.Value.Set() interpreting that as a string we need to remove
			// the brackets
			value := i.GetValue()
			if f.Value.Type() == "stringSlice" {
				value = strings.Trim(value, "[]")
			}

			f.Value.Set(value)
			f.Changed = true
		}
	}
}

func repairConfigs(configs *pb.All) {
	// Repair the "install" section; install flags are updated separately
	if configs.Install == nil {
		configs.Install = &pb.Install{}
	}
	// ALWAYS update the CLI version to the most recent.
	configs.Install.CliVersion = version.Version

	// Repair the "proxy" section
	if configs.Proxy == nil {
		configs.Proxy = &pb.Proxy{}
	}
	if configs.Proxy.DebugImage == nil {
		configs.Proxy.DebugImage = &pb.Image{}
	}
	if configs.GetProxy().GetDebugImage().GetImageName() == "" {
		configs.Proxy.DebugImage.ImageName = k8s.DebugSidecarImage
	}
	if configs.GetProxy().GetDebugImageVersion() == "" {
		configs.Proxy.DebugImageVersion = version.Version
	}
}

func injectCABundle(k *k8s.KubernetesAPI, webhook string, value *charts.TLS) error {

	var err error

	switch webhook {
	case k8s.ProxyInjectorWebhookServiceName:
		err = injectCABundleFromMutatingWebhook(k, k8s.ProxyInjectorWebhookConfigName, value)
	case k8s.SPValidatorWebhookServiceName:
		err = injectCABundleFromValidatingWebhook(k, k8s.SPValidatorWebhookConfigName, value)
	case k8s.TapServiceName:
		err = injectCABundleFromAPIService(k, k8s.TapAPIRegistrationServiceName, value)
	default:
		err = fmt.Errorf("unknown webhook for retrieving CA bundle: %s", webhook)
	}

	// anything other than the resource not being found: propagate error back up the stack.
	if !kerrors.IsNotFound(err) {
		return err
	}

	// if the resource is missing, simply use the existing cert.
	value.CaBundle = value.CrtPEM
	return nil
}

func injectCABundleFromMutatingWebhook(k kubernetes.Interface, resource string, value *charts.TLS) error {
	webhookConf, err := k.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().Get(resource, metav1.GetOptions{})
	if err != nil {
		return err
	}

	// note: this assumes that there will ever only be one service defined per webhook configuration
	value.CaBundle = string(webhookConf.Webhooks[0].ClientConfig.CABundle)

	return nil
}

func injectCABundleFromValidatingWebhook(k kubernetes.Interface, resource string, value *charts.TLS) error {
	webhookConf, err := k.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Get(resource, metav1.GetOptions{})
	if err != nil {
		return err
	}

	value.CaBundle = string(webhookConf.Webhooks[0].ClientConfig.CABundle)
	return nil
}

func injectCABundleFromAPIService(k *k8s.KubernetesAPI, resource string, value *charts.TLS) error {
	apiService, err := k.Apiregistration.ApiregistrationV1().APIServices().Get(resource, metav1.GetOptions{})
	if err != nil {
		return err
	}

	value.CaBundle = string(apiService.Spec.CABundle)
	return nil
}

func fetchTLSSecret(k *k8s.KubernetesAPI, webhook string) (*charts.TLS, error) {
	secret, err := k.CoreV1().
		Secrets(controlPlaneNamespace).
		Get(webhookSecretName(webhook), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	value := &charts.TLS{
		KeyPEM: string(secret.Data["key.pem"]),
		CrtPEM: string(secret.Data["crt.pem"]),
	}

	if err := injectCABundle(k, webhook, value); err != nil {
		return nil, err
	}

	if err := verifyWebhookTLS(value, webhook); err != nil {
		return nil, err
	}

	return value, nil
}

// fetchIdentityValue checks the kubernetes API to fetch an existing
// linkerd identity configuration.
//
// This bypasses the public API so that we can access secrets and validate
// permissions.
func fetchIdentityValues(k kubernetes.Interface, options *upgradeOptions, idctx *pb.IdentityContext, values *charts.Values) error {
	if idctx == nil {
		return nil
	}

	if idctx.Scheme == "" {
		// if this is empty, then we are upgrading from a version
		// that did not support issuer schemes. Just default to the
		// linkerd one.
		idctx.Scheme = k8s.IdentityIssuerSchemeLinkerd
	}

	var trustAnchorsPEM string
	var issuerData *issuercerts.IssuerCertData
	var err error

	trustAnchorsPEM = idctx.GetTrustAnchorsPem()

	issuerData, err = fetchIssuer(k, trustAnchorsPEM, idctx.Scheme)
	if err != nil {
		return err
	}

	values.Global.IdentityTrustAnchorsPEM = trustAnchorsPEM
	values.Identity.Issuer.Scheme = idctx.Scheme
	values.Identity.Issuer.ClockSkewAllowance = idctx.GetClockSkewAllowance().String()
	values.Identity.Issuer.IssuanceLifetime = idctx.GetIssuanceLifetime().String()
	values.Identity.Issuer.CrtExpiry = *issuerData.Expiry
	values.Identity.Issuer.TLS.KeyPEM = issuerData.IssuerKey
	values.Identity.Issuer.TLS.CrtPEM = issuerData.IssuerCrt

	return nil
}

func readIssuer(trustPEM, issuerCrtPath, issuerKeyPath string) (*issuercerts.IssuerCertData, error) {
	key, crt, err := issuercerts.LoadIssuerCrtAndKeyFromFiles(issuerKeyPath, issuerCrtPath)
	if err != nil {
		return nil, err
	}
	issuerData := &issuercerts.IssuerCertData{
		TrustAnchors: trustPEM,
		IssuerCrt:    crt,
		IssuerKey:    key,
	}

	return issuerData, nil
}

func fetchIssuer(k kubernetes.Interface, trustPEM string, scheme string) (*issuercerts.IssuerCertData, error) {
	var (
		issuerData *issuercerts.IssuerCertData
		err        error
	)
	switch scheme {
	case string(corev1.SecretTypeTLS):
		issuerData, err = issuercerts.FetchExternalIssuerData(k, controlPlaneNamespace)
	default:
		issuerData, err = issuercerts.FetchIssuerData(k, trustPEM, controlPlaneNamespace)
		if issuerData != nil && issuerData.TrustAnchors != trustPEM {
			issuerData.TrustAnchors = trustPEM
		}
	}
	if err != nil {
		return nil, err
	}

	return issuerData, nil
}

func webhookCommonName(webhook string) string {
	return fmt.Sprintf("%s.%s.svc", webhook, controlPlaneNamespace)
}

func webhookSecretName(webhook string) string {
	return fmt.Sprintf("%s-tls", webhook)
}

func verifyWebhookTLS(value *charts.TLS, webhook string) error {
	crt, err := tls.DecodePEMCrt(value.CrtPEM)
	if err != nil {
		return err
	}
	anchors := crt.CertPool()
	if err := crt.Verify(anchors, webhookCommonName(webhook), time.Time{}); err != nil {
		return err
	}

	return nil
}
