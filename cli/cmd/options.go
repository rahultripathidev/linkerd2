package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	l5dcharts "github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	"github.com/linkerd/linkerd2/pkg/issuercerts"
	"github.com/linkerd/linkerd2/pkg/k8s"
	consts "github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/tls"
	"github.com/linkerd/linkerd2/pkg/tree"
	"github.com/linkerd/linkerd2/pkg/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/helm/pkg/chartutil"
	"sigs.k8s.io/yaml"
)

type (
	// These option structs hold the values of the CLI flags.  Each field in
	// an options struct corresponds to a single CLI flag.  We split these
	// across several different structs because different commands have
	// different (but overlapping) sets of flags.  This division allows us to
	// reuse shared flags between commands.
	//
	// When a set of flags is initialized, its default values are taken from
	// a Values struct.  After flags have been parsed and validated, the flag
	// values in the options struct can be copied onto the Values struct.
	// Since the flag defaults were set from the Values struct to begin with,
	// the only Values fields which will change are the ones that correspond
	// to a flag which was explicitly set.

	// allStageOptions holds the values for flags which are used in both the
	// "install config" stage and in the "install control-plane" stage.  These
	// flags are available at upgrade time as well.
	allStageOptions struct {
		cniEnabled                  bool
		restrictDashboardPrivileges bool
		addOnConfig                 string
	}

	// installOptions holds the values for flags which are used in the
	// "install control-plane" stage but are not available during upgrade.
	installOptions struct {
		clusterDomain          string
		identityExternalIssuer bool
		trustDomain            string
	}

	// installUpgradeOptions holds the values for falgs which are used in the
	// "install control-plane" stage and are also available during upgrade.
	installUpgradeOptions struct {
		controlPlaneVersion    string
		controllerReplicas     uint
		controllerLogLevel     string
		highAvailability       bool
		controllerUID          int64
		disableH2Upgrade       bool
		disableHeartbeat       bool
		enableEndpointSlices   bool
		omitWebhookSideEffects bool
		controlPlaneTracing    bool
		identityOptions        *installIdentityOptions
		*proxyConfigOptions
		*installOptions
	}

	installIdentityOptions struct {
		trustPEMFile, crtPEMFile, keyPEMFile string

		issuanceLifetime   time.Duration
		clockSkewAllowance time.Duration
	}

	// helper struct to move those values together
	identityWithAnchors struct {
		Identity        *l5dcharts.Identity
		TrustAnchorsPEM string
	}
)

/* Flag initialization */

func makeInstallUpgradeFlags(defaults *l5dcharts.Values) (*pflag.FlagSet, *installUpgradeOptions, error) {
	var options installUpgradeOptions

	installFlags, installOptions := makeInstallFlags(defaults)

	flags := pflag.NewFlagSet("install", pflag.ExitOnError)
	flags.AddFlagSet(options.proxyConfigOptions.flagSet(pflag.ExitOnError))
	flags.AddFlagSet(installFlags)

	options.installOptions = installOptions

	flags.UintVar(
		&options.controllerReplicas, "controller-replicas", defaults.ControllerReplicas,
		"Replicas of the controller to deploy",
	)

	flags.StringVar(
		&options.controllerLogLevel, "controller-log-level", defaults.Global.ControllerLogLevel,
		"Log level for the controller and web components",
	)

	flags.BoolVar(
		&options.highAvailability, "ha", false,
		"Enable HA deployment config for the control plane (default false)",
	)

	flags.Int64Var(
		&options.controllerUID, "controller-uid", defaults.ControllerUID,
		"Run the control plane components under this user ID",
	)

	flags.BoolVar(
		&options.disableH2Upgrade, "disable-h2-upgrade", !defaults.EnableH2Upgrade,
		"Prevents the controller from instructing proxies to perform transparent HTTP/2 upgrading (default false)",
	)

	flags.BoolVar(
		&options.disableHeartbeat, "disable-heartbeat", defaults.DisableHeartBeat,
		"Disables the heartbeat cronjob (default false)",
	)

	issuanceLifetime, err := time.ParseDuration(defaults.Identity.Issuer.IssuanceLifetime)
	if err != nil {
		return nil, nil, err
	}
	flags.DurationVar(
		&options.identityOptions.issuanceLifetime, "identity-issuance-lifetime", issuanceLifetime,
		"The amount of time for which the Identity issuer should certify identity",
	)

	clockSkewAllowance, err := time.ParseDuration(defaults.Identity.Issuer.ClockSkewAllowance)
	if err != nil {
		return nil, nil, err
	}
	flags.DurationVar(
		&options.identityOptions.clockSkewAllowance, "identity-clock-skew-allowance", clockSkewAllowance,
		"The amount of time to allow for clock skew within a Linkerd cluster",
	)

	flags.BoolVar(
		&options.omitWebhookSideEffects, "omit-webhook-side-effects", defaults.OmitWebhookSideEffects,
		"Omit the sideEffects flag in the webhook manifests, This flag must be provided during install or upgrade for Kubernetes versions pre 1.12",
	)

	flags.BoolVar(
		&options.controlPlaneTracing, "control-plane-tracing", defaults.Global.ControlPlaneTracing,
		"Enables Control Plane Tracing with the defaults",
	)

	flags.StringVar(
		&options.identityOptions.crtPEMFile, "identity-issuer-certificate-file", "",
		"A path to a PEM-encoded file containing the Linkerd Identity issuer certificate (generated by default)",
	)

	flags.StringVar(
		&options.identityOptions.keyPEMFile, "identity-issuer-key-file", "",
		"A path to a PEM-encoded file containing the Linkerd Identity issuer private key (generated by default)",
	)

	flags.StringVar(
		&options.identityOptions.trustPEMFile, "identity-trust-anchors-file", "",
		"A path to a PEM-encoded file containing Linkerd Identity trust anchors (generated by default)",
	)

	flags.BoolVar(&options.enableEndpointSlices, "enable-endpoint-slices", defaults.Global.EnableEndpointSlices,
		"Enables the usage of EndpointSlice informers and resources for destination service")

	flags.StringVarP(&options.controlPlaneVersion, "control-plane-version", "", defaults.ControllerImageVersion, "Tag to be used for the control plane component images")

	// Hide developer focused flags in release builds.
	release, err := version.IsReleaseChannel(version.Version)
	if err != nil {
		log.Errorf("Unable to parse version: %s", version.Version)
	}
	if release {
		flags.MarkHidden("control-plane-version")
		flags.MarkHidden("proxy-image")
		flags.MarkHidden("proxy-version")
		flags.MarkHidden("image-pull-policy")
		flags.MarkHidden("init-image")
		flags.MarkHidden("init-image-version")
	}

	flags.MarkHidden("control-plane-tracing")
	return flags, &options, nil
}

func makeAllStageFlags(defaults *l5dcharts.Values) (*pflag.FlagSet, *allStageOptions) {
	var options allStageOptions
	flags := pflag.NewFlagSet("all-stage", pflag.ExitOnError)

	flags.BoolVar(&options.cniEnabled, "linkerd-cni-enabled", defaults.Global.CNIEnabled,
		"Omit the NET_ADMIN capability in the PSP and the proxy-init container when injecting the proxy; requires the linkerd-cni plugin to already be installed",
	)

	flags.BoolVar(
		&options.restrictDashboardPrivileges, "restrict-dashboard-privileges", defaults.RestrictDashboardPrivileges,
		"Restrict the Linkerd Dashboard's default privileges to disallow Tap and Check",
	)

	flags.StringVar(
		&options.addOnConfig, "addon-config", "",
		"A path to a configuration file of add-ons. If add-on config already exists, this new config gets merged with the existing one (unless --addon-overwrite is used)",
	)

	return flags, &options
}

func makeInstallFlags(defaults *l5dcharts.Values) (*pflag.FlagSet, *installOptions) {
	var options installOptions
	flags := pflag.NewFlagSet("install-only", pflag.ExitOnError)

	flags.StringVar(
		&options.clusterDomain, "cluster-domain", defaults.Global.ClusterDomain,
		"Set custom cluster domain",
	)
	flags.StringVar(
		&options.trustDomain, "identity-trust-domain", defaults.Global.IdentityTrustDomain,
		"Configures the name suffix used for identities.",
	)
	flags.BoolVar(
		&options.identityExternalIssuer, "identity-external-issuer", false,
		"Whether to use an external identity issuer (default false)",
	)
	return flags, &options
}

// upgradeOnlyFlagSet includes flags that are only accessible at upgrade-time
// and not at install-time. also these flags are not intended to be persisted
// via linkerd-config ConfigMap, unlike recordableFlagSet
func makeUpgradeFlags() (*pflag.FlagSet, *upgradeOptions) {
	var options upgradeOptions
	flags := pflag.NewFlagSet("upgrade-only", pflag.ExitOnError)

	flags.StringVar(
		&options.manifests, "from-manifests", "",
		"Read config from a Linkerd install YAML rather than from Kubernetes",
	)
	flags.BoolVar(
		&options.force, "force", false,
		"Force upgrade operation even when issuer certificate does not work with the trust anchors of all proxies",
	)
	flags.BoolVar(
		&options.addOnOverwrite, "addon-overwrite", false,
		"Overwrite (instead of merge) existing add-ons config with file in --addon-config (or reset to defaults if no new config is passed)",
	)
	return flags, &options
}

/* Option validation */

func (options *installOptions) validate(ignoreCluster bool) error {
	if ignoreCluster && options.identityExternalIssuer {
		return errors.New("--ignore-cluster is not supported when --identity-external-issuer=true")
	}
	return nil
}

func (options *installUpgradeOptions) validate() error {
	if options.controlPlaneVersion != "" && !alphaNumDashDot.MatchString(options.controlPlaneVersion) {
		return fmt.Errorf("%s is not a valid version", options.controlPlaneVersion)
	}

	if options.identityOptions == nil {
		// Programmer error: identityOptions may be empty, but it must be set by the constructor.
		panic("missing identity options")
	}

	if _, err := log.ParseLevel(options.controllerLogLevel); err != nil {
		return fmt.Errorf("--controller-log-level must be one of: panic, fatal, error, warn, info, debug")
	}

	if err := options.proxyConfigOptions.validate(); err != nil {
		return err
	}
	if options.proxyLogLevel == "" {
		return errors.New("--proxy-log-level must not be empty")
	}

	if options.enableEndpointSlices {
		k8sAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
		if err != nil {
			return err
		}

		err = k8s.EndpointSliceAccess(k8sAPI)
		if err != nil {
			return err
		}
	}

	err := options.identityOptions.validate(options.identityExternalIssuer, options.trustDomain)
	if err != nil {
		return err
	}

	return nil
}

func (idopts *installIdentityOptions) validate(externallyManaged bool, trustDomain string) error {
	if idopts == nil {
		return nil
	}

	if trustDomain != "" {
		if errs := validation.IsDNS1123Subdomain(trustDomain); len(errs) > 0 {
			return fmt.Errorf("invalid trust domain '%s': %s", trustDomain, errs[0])
		}
	}

	if externallyManaged {

		if idopts.crtPEMFile != "" {
			return errors.New("--identity-issuer-certificate-file must not be specified if --identity-external-issuer=true")
		}

		if idopts.keyPEMFile != "" {
			return errors.New("--identity-issuer-key-file must not be specified if --identity-external-issuer=true")
		}

		if idopts.trustPEMFile != "" {
			return errors.New("--identity-trust-anchors-file must not be specified if --identity-external-issuer=true")
		}

	} else {
		if idopts.trustPEMFile != "" || idopts.crtPEMFile != "" || idopts.keyPEMFile != "" {
			if idopts.trustPEMFile == "" {
				return errors.New("a trust anchors file must be specified if other credentials are provided")
			}
			if idopts.crtPEMFile == "" {
				return errors.New("a certificate file must be specified if other credentials are provided")
			}
			if idopts.keyPEMFile == "" {
				return errors.New("a private key file must be specified if other credentials are provided")
			}
			if err := checkFilesExist([]string{idopts.trustPEMFile, idopts.crtPEMFile, idopts.keyPEMFile}); err != nil {
				return err
			}
		}
	}

	return nil
}

/* the applyToValues functions copy flag values onto the Values struct */

func (options *allStageOptions) applyToValues(values *l5dcharts.Values) error {
	values.Global.CNIEnabled = options.cniEnabled
	values.RestrictDashboardPrivileges = options.restrictDashboardPrivileges

	if options.addOnConfig != "" {
		addOnValues, err := read(options.addOnConfig)
		if err != nil {
			return err
		}

		if len(addOnValues) != 1 {
			return fmt.Errorf("Excepted a single configuration file, but got 0 or many")
		}

		addOnValuesRaw, err := ioutil.ReadAll(addOnValues[0])
		if err != nil {
			return err
		}

		rawValues, err := yaml.Marshal(values)
		if err != nil {
			return err
		}

		// Merge Add-On Values with Values
		finalValues, err := mergeRaw(rawValues, addOnValuesRaw)
		if err != nil {
			return err
		}

		err = yaml.Unmarshal(finalValues, values)
		if err != nil {
			return err
		}
	}
	return nil
}

func (options *installOptions) applyToValues(values *l5dcharts.Values) {
	values.Global.ClusterDomain = options.clusterDomain
	values.Global.IdentityTrustDomain = options.trustDomain
	if options.identityExternalIssuer {
		values.Identity.Issuer.Scheme = string(corev1.SecretTypeTLS)
	} else {
		values.Identity.Issuer.Scheme = consts.IdentityIssuerSchemeLinkerd
	}
}

func (options *installUpgradeOptions) applyToValues(values *l5dcharts.Values) error {

	options.installOptions.applyToValues(values)

	values.ControllerImage = fmt.Sprintf("%s/controller", options.dockerRegistry)
	if options.controlPlaneVersion != version.Version {
		values.Global.ControllerImageVersion = options.controlPlaneVersion
	}
	values.Global.ControllerLogLevel = options.controllerLogLevel
	values.ControllerReplicas = options.controllerReplicas
	values.ControllerUID = options.controllerUID
	values.Global.ControlPlaneTracing = options.controlPlaneTracing
	values.EnableH2Upgrade = !options.disableH2Upgrade
	values.EnablePodAntiAffinity = options.highAvailability
	values.Global.HighAvailability = options.highAvailability
	values.Global.ImagePullPolicy = options.imagePullPolicy
	values.Global.Namespace = controlPlaneNamespace
	values.Global.EnableEndpointSlices = options.enableEndpointSlices
	values.OmitWebhookSideEffects = options.omitWebhookSideEffects
	values.DisableHeartBeat = options.disableHeartbeat
	values.WebImage = fmt.Sprintf("%s/web", options.dockerRegistry)
	if options.dockerRegistry != "gcr.io/linkerd-io" {
		if values.Grafana["image"] == nil {
			values.Grafana["image"] = map[string]interface{}{}
		}
		values.Grafana["image"].(map[string]interface{})["name"] = fmt.Sprintf("%s/grafana", options.dockerRegistry)
	}

	values.Global.Proxy = &l5dcharts.Proxy{
		DestinationGetNetworks: strings.Join(options.destinationGetNetworks, ","),
		EnableExternalProfiles: options.enableExternalProfiles,
		OutboundConnectTimeout: options.outboundConnectTimeout,
		InboundConnectTimeout:  options.inboundConnectTimeout,
		Image: &l5dcharts.Image{
			Name:       registryOverride(options.proxyImage, options.dockerRegistry),
			PullPolicy: options.imagePullPolicy,
			Version:    options.proxyVersion,
		},
		LogLevel:  options.proxyLogLevel,
		LogFormat: options.proxyLogFormat,
		Ports: &l5dcharts.Ports{
			Admin:    int32(options.proxyAdminPort),
			Control:  int32(options.proxyControlPort),
			Inbound:  int32(options.proxyInboundPort),
			Outbound: int32(options.proxyOutboundPort),
		},
		Resources: &l5dcharts.Resources{
			CPU: l5dcharts.Constraints{
				Limit:   options.proxyCPULimit,
				Request: options.proxyCPURequest,
			},
			Memory: l5dcharts.Constraints{
				Limit:   options.proxyMemoryLimit,
				Request: options.proxyMemoryRequest,
			},
		},
		UID:   options.proxyUID,
		Trace: values.Global.Proxy.Trace,
	}

	values.Global.ProxyInit.Image.Name = registryOverride(options.initImage, options.dockerRegistry)
	values.Global.ProxyInit.Image.PullPolicy = options.imagePullPolicy
	values.Global.ProxyInit.Image.Version = options.initImageVersion
	values.Global.ProxyInit.IgnoreInboundPorts = strings.Join(options.ignoreInboundPorts, ",")
	values.Global.ProxyInit.IgnoreOutboundPorts = strings.Join(options.ignoreOutboundPorts, ",")
	values.Global.ProxyInit.XTMountPath = &l5dcharts.VolumeMountPath{
		MountPath: k8s.MountPathXtablesLock,
		Name:      k8s.InitXtablesLockVolumeMountName,
	}

	values.DebugContainer.Image.Name = registryOverride(options.debugImage, options.dockerRegistry)
	values.DebugContainer.Image.PullPolicy = options.imagePullPolicy
	values.DebugContainer.Image.Version = options.debugImageVersion

	if options.highAvailability {
		haValues, err := l5dcharts.NewValues(true)
		if err != nil {
			return err
		}
		// use the HA defaults if CLI options aren't provided
		if options.controllerReplicas == 1 {
			values.ControllerReplicas = haValues.ControllerReplicas
		}

		if options.proxyCPURequest == "" {
			values.Global.Proxy.Resources.CPU.Request = haValues.Global.Proxy.Resources.CPU.Request
		}

		if options.proxyMemoryRequest == "" {
			values.Global.Proxy.Resources.Memory.Request = haValues.Global.Proxy.Resources.Memory.Request
		}

		if options.proxyCPULimit == "" {
			values.Global.Proxy.Resources.CPU.Limit = haValues.Global.Proxy.Resources.CPU.Limit
		}

		if options.proxyMemoryLimit == "" {
			values.Global.Proxy.Resources.Memory.Limit = haValues.Global.Proxy.Resources.Memory.Limit
		}
	}

	// Some of the heartbeat Prometheus queries rely on 5m resolution, which
	// means at least 5 minutes of data available. Start the first CronJob 10
	// minutes after `linkerd install` is run, to give the user 5 minutes to
	// install.
	t := time.Now().Add(10 * time.Minute).UTC()
	values.HeartbeatSchedule = fmt.Sprintf("%d %d * * * ", t.Minute(), t.Hour())

	externallyManaged := values.Identity.Issuer.Scheme == string(corev1.SecretTypeTLS)
	identity, err := options.identityOptions.build(externallyManaged, values.Global.IdentityTrustDomain)
	if err != nil {
		return err
	}
	values.Identity = identity.Identity
	values.Global.IdentityTrustAnchorsPEM = identity.TrustAnchorsPEM

	return nil
}

func (idopts *installIdentityOptions) build(externallyManaged bool, trustDomain string) (*identityWithAnchors, error) {
	if idopts == nil {
		return nil, nil
	}

	if externallyManaged {
		return idopts.readExternallyManaged(trustDomain)
	} else if idopts.trustPEMFile != "" && idopts.crtPEMFile != "" && idopts.keyPEMFile != "" {
		return idopts.readValues(trustDomain)
	} else {
		return idopts.genValues(trustDomain)
	}
}

func (options *allStageOptions) toOverrides() (tree.Tree, error) {
	defaults, err := l5dcharts.NewValues(false)
	if err != nil {
		return nil, err
	}
	values, err := l5dcharts.NewValues(false)
	if err != nil {
		return nil, err
	}
	err = options.applyToValues(values)
	if err != nil {
		return nil, err
	}
	defaultsTree, err := tree.MarshalToTree(defaults)
	if err != nil {
		return nil, err
	}
	valuesTree, err := tree.MarshalToTree(values)
	if err != nil {
		return nil, err
	}
	return defaultsTree.Diff(valuesTree)
}

func (options *installUpgradeOptions) toOverrides() (tree.Tree, error) {
	defaults, err := l5dcharts.NewValues(false)
	if err != nil {
		return nil, err
	}
	values, err := l5dcharts.NewValues(false)
	if err != nil {
		return nil, err
	}
	err = options.applyToValues(values)
	if err != nil {
		return nil, err
	}
	defaultsTree, err := tree.MarshalToTree(defaults)
	if err != nil {
		return nil, err
	}
	valuesTree, err := tree.MarshalToTree(values)
	if err != nil {
		return nil, err
	}
	return defaultsTree.Diff(valuesTree)
}

func (options *allStageOptions) overrideValues(values *l5dcharts.Values) error {
	overrides, err := options.toOverrides()
	if err != nil {
		return err
	}
	return overrides.MarshalOnto(values)
}

func (options *installUpgradeOptions) overrideValues(values *l5dcharts.Values) error {
	overrides, err := options.toOverrides()
	if err != nil {
		return err
	}
	return overrides.MarshalOnto(values)
}

/* Identity */

func (idopts *installIdentityOptions) issuerName(trustDomain string) string {
	return fmt.Sprintf("identity.%s.%s", controlPlaneNamespace, trustDomain)
}

func (idopts *installIdentityOptions) genValues(trustDomain string) (*identityWithAnchors, error) {
	root, err := tls.GenerateRootCAWithDefaults(idopts.issuerName(trustDomain))
	if err != nil {
		return nil, fmt.Errorf("failed to generate root certificate for identity: %s", err)
	}

	return &identityWithAnchors{
		TrustAnchorsPEM: root.Cred.Crt.EncodeCertificatePEM(),
		Identity: &l5dcharts.Identity{
			Issuer: &l5dcharts.Issuer{
				Scheme:              consts.IdentityIssuerSchemeLinkerd,
				ClockSkewAllowance:  idopts.clockSkewAllowance.String(),
				IssuanceLifetime:    idopts.issuanceLifetime.String(),
				CrtExpiry:           root.Cred.Crt.Certificate.NotAfter,
				CrtExpiryAnnotation: k8s.IdentityIssuerExpiryAnnotation,
				TLS: &l5dcharts.IssuerTLS{
					KeyPEM: root.Cred.EncodePrivateKeyPEM(),
					CrtPEM: root.Cred.Crt.EncodeCertificatePEM(),
				},
			},
		},
	}, nil
}

func (idopts *installIdentityOptions) readExternallyManaged(trustDomain string) (*identityWithAnchors, error) {

	kubeAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
	if err != nil {
		return nil, fmt.Errorf("error fetching external issuer config: %s", err)
	}

	externalIssuerData, err := issuercerts.FetchExternalIssuerData(kubeAPI, controlPlaneNamespace)
	if err != nil {
		return nil, err
	}
	_, err = externalIssuerData.VerifyAndBuildCreds(idopts.issuerName(trustDomain))
	if err != nil {
		return nil, fmt.Errorf("failed to read CA from %s: %s", consts.IdentityIssuerSecretName, err)
	}

	return &identityWithAnchors{
		TrustAnchorsPEM: externalIssuerData.TrustAnchors,
		Identity: &l5dcharts.Identity{
			Issuer: &l5dcharts.Issuer{
				Scheme:             string(corev1.SecretTypeTLS),
				ClockSkewAllowance: idopts.clockSkewAllowance.String(),
				IssuanceLifetime:   idopts.issuanceLifetime.String(),
			},
		},
	}, nil

}

// readValues attempts to read an issuer configuration from disk
// to produce an `installIdentityValues`.
//
// The identity options must have already been validated.
func (idopts *installIdentityOptions) readValues(trustDomain string) (*identityWithAnchors, error) {
	issuerData, err := issuercerts.LoadIssuerDataFromFiles(idopts.keyPEMFile, idopts.crtPEMFile, idopts.trustPEMFile)
	if err != nil {
		return nil, err
	}

	creds, err := issuerData.VerifyAndBuildCreds(idopts.issuerName(trustDomain))
	if err != nil {
		return nil, fmt.Errorf("failed to verify issuer certs stored on disk: %s", err)
	}

	return &identityWithAnchors{
		TrustAnchorsPEM: issuerData.TrustAnchors,
		Identity: &l5dcharts.Identity{
			Issuer: &l5dcharts.Issuer{
				Scheme:              consts.IdentityIssuerSchemeLinkerd,
				ClockSkewAllowance:  idopts.clockSkewAllowance.String(),
				IssuanceLifetime:    idopts.issuanceLifetime.String(),
				CrtExpiry:           creds.Crt.Certificate.NotAfter,
				CrtExpiryAnnotation: k8s.IdentityIssuerExpiryAnnotation,
				TLS: &l5dcharts.IssuerTLS{
					KeyPEM: creds.EncodePrivateKeyPEM(),
					CrtPEM: creds.EncodeCertificatePEM(),
				},
			},
		},
	}, nil
}

/* Helpers */

func mergeRaw(a, b []byte) ([]byte, error) {
	var aMap, bMap chartutil.Values

	err := yaml.Unmarshal(a, &aMap)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(b, &bMap)
	if err != nil {
		return nil, err
	}

	aMap.MergeInto(bMap)
	return yaml.Marshal(aMap)

}
