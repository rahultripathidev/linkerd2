package cmd

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"

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
	allStageFlags, allStageOptions := makeAllStageFlags(values)
	flags, installUpgradeOptions, err := makeInstallUpgradeFlags(values)
	if err != nil {
		return nil, err
	}

	setFlagsFromInstall(allStageFlags, configs.GetInstall().GetFlags())
	setFlagsFromInstall(flags, configs.GetInstall().GetFlags())

	installUpgradeOptions.overrideConfigs(configs, map[string]string{})

	err = allStageOptions.applyToValues(values)
	err = installUpgradeOptions.applyToValues(values)
	if err != nil {
		return nil, err
	}

	var identity *identityWithAnchors
	idctx := configs.GetGlobal().GetIdentityContext()
	if idctx.GetTrustDomain() == "" || idctx.GetTrustAnchorsPem() == "" {
		// If there wasn't an idctx, or if it doesn't specify the required fields, we
		// must be upgrading from a version that didn't support identity, so generate it anew...
		identity, err = installUpgradeOptions.identityOptions.genValues(installUpgradeOptions.trustDomain)
		if err != nil {
			return nil, err
		}
	} else {
		identity, err = fetchIdentityValues(k, upgradeOptions, installUpgradeOptions.identityOptions, idctx)
		if err != nil {
			return nil, err
		}
	}

	values.Identity = identity.Identity
	values.Global.IdentityTrustAnchorsPEM = identity.TrustAnchorsPEM

	if !upgradeOptions.addOnOverwrite {
		// Update Add-Ons Configuration from the linkerd-value cm
		cmRawValues, _ := k8s.GetAddOnsConfigMap(k, controlPlaneNamespace)
		if cmRawValues != nil {
			//Cm is present now get the data
			cmData, ok := cmRawValues["values"]
			if !ok {
				return nil, fmt.Errorf("values subpath not found in %s configmap", k8s.AddOnsConfigMapName)
			}
			rawValues, err := yaml.Marshal(values)
			if err != nil {
				return nil, err
			}

			// over-write add-on values with cmValues
			// Merge Add-On Values with Values
			if rawValues, err = mergeRaw(rawValues, []byte(cmData)); err != nil {
				return nil, err
			}

			if err = yaml.Unmarshal(rawValues, &values); err != nil {
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

func fetchTLSSecret(k *k8s.KubernetesAPI, webhook string, options *installIdentityOptions) (*charts.TLS, error) {
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

func ensureIssuerCertWorksWithAllProxies(k kubernetes.Interface, cred *tls.Cred) error {
	meshedPods, err := healthcheck.GetMeshedPodsIdentityData(k, "")
	var problematicPods []string
	if err != nil {
		return err
	}
	for _, pod := range meshedPods {
		anchors, err := tls.DecodePEMCertPool(pod.Anchors)

		if anchors != nil {
			err = cred.Verify(anchors, "", time.Time{})
		}

		if err != nil {
			problematicPods = append(problematicPods, fmt.Sprintf("* %s/%s", pod.Namespace, pod.Name))
		}
	}

	if len(problematicPods) > 0 {
		errorMessageHeader := "You are attempting to use an issuer certificate which does not validate against the trust anchors of the following pods:"
		errorMessageFooter := "These pods do not have the current trust bundle and must be restarted.  Use the --force flag to proceed anyway (this will likely prevent those pods from sending or receiving traffic)."
		return fmt.Errorf("%s\n\t%s\n%s", errorMessageHeader, strings.Join(problematicPods, "\n\t"), errorMessageFooter)
	}
	return nil
}

// fetchIdentityValue checks the kubernetes API to fetch an existing
// linkerd identity configuration.
//
// This bypasses the public API so that we can access secrets and validate
// permissions.
func fetchIdentityValues(k kubernetes.Interface, options *upgradeOptions, identityOptions *installIdentityOptions, idctx *pb.IdentityContext) (*identityWithAnchors, error) {
	if idctx == nil {
		return nil, nil
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

	if identityOptions.trustPEMFile != "" {
		trustb, err := ioutil.ReadFile(identityOptions.trustPEMFile)
		if err != nil {
			return nil, err
		}
		trustAnchorsPEM = string(trustb)
	} else {
		trustAnchorsPEM = idctx.GetTrustAnchorsPem()
	}

	updatingIssuerCert := identityOptions.crtPEMFile != "" && identityOptions.keyPEMFile != ""

	if updatingIssuerCert {
		issuerData, err = readIssuer(trustAnchorsPEM, identityOptions.crtPEMFile, identityOptions.keyPEMFile)
	} else {
		issuerData, err = fetchIssuer(k, trustAnchorsPEM, idctx.Scheme)
	}
	if err != nil {
		return nil, err
	}

	cred, err := issuerData.VerifyAndBuildCreds("")
	if err != nil {
		return nil, fmt.Errorf("issuer certificate does not work with the provided anchors: %s\nFor more information: https://linkerd.io/2/tasks/rotating_identity_certificates/", err)
	}
	issuerData.Expiry = &cred.Crt.Certificate.NotAfter

	if updatingIssuerCert && !options.force {
		if err := ensureIssuerCertWorksWithAllProxies(k, cred); err != nil {
			return nil, err
		}
	}

	return &identityWithAnchors{
		TrustAnchorsPEM: trustAnchorsPEM,
		Identity: &charts.Identity{

			Issuer: &charts.Issuer{
				Scheme:              idctx.Scheme,
				ClockSkewAllowance:  idctx.GetClockSkewAllowance().String(),
				IssuanceLifetime:    idctx.GetIssuanceLifetime().String(),
				CrtExpiry:           *issuerData.Expiry,
				CrtExpiryAnnotation: k8s.IdentityIssuerExpiryAnnotation,
				TLS: &charts.IssuerTLS{
					KeyPEM: issuerData.IssuerKey,
					CrtPEM: issuerData.IssuerCrt,
				},
			},
		},
	}, nil

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
