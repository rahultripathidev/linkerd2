package cmd

import (
	"errors"
	"flag"

	"fmt"
	"io/ioutil"
	"net"
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
	k8sResource "k8s.io/apimachinery/pkg/api/resource"
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

	// proxyConfigOptions holds values for command line flags that apply to both the
	// install and inject commands. All fields in this struct should have
	// corresponding flags added in the addProxyConfigFlags func later in this file.
	proxyConfigOptions struct {
		proxyVersion                  string
		proxyImage                    string
		initImage                     string
		initImageVersion              string
		debugImage                    string
		debugImageVersion             string
		dockerRegistry                string
		imagePullPolicy               string
		destinationGetNetworks        []string
		ignoreInboundPorts            []string
		ignoreOutboundPorts           []string
		proxyUID                      int64
		proxyLogLevel                 string
		proxyLogFormat                string
		proxyInboundPort              uint
		proxyOutboundPort             uint
		proxyControlPort              uint
		proxyAdminPort                uint
		proxyCPURequest               string
		proxyMemoryRequest            string
		proxyCPULimit                 string
		proxyMemoryLimit              string
		enableExternalProfiles        bool
		traceCollector                string
		traceCollectorSvcAccount      string
		waitBeforeExitSeconds         uint64
		disableIdentity               bool
		requireIdentityOnInboundPorts []string
		disableTap                    bool
		inboundConnectTimeout         string
		outboundConnectTimeout        string
	}
)

/* Flag initialization */

func makeInstallUpgradeFlags(flags *pflag.FlagSet, defaults *l5dcharts.Values) ([]flag.Flag, error) {
	var options installUpgradeOptions

	installFlags, installOptions := makeInstallFlags(defaults)
	proxyFlags, proxyOptions := makeProxyFlags(pflag.ExitOnError, defaults)

	flags := pflag.NewFlagSet("install", pflag.ExitOnError)
	options.proxyConfigOptions = proxyOptions
	options.identityOptions = &installIdentityOptions{}
	flags.AddFlagSet(proxyFlags)
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

func makeProxyFlags(e pflag.ErrorHandling, defaults *l5dcharts.Values) (*pflag.FlagSet, *proxyConfigOptions) {
	var options proxyConfigOptions
	flags := pflag.NewFlagSet("proxy", e)

	flags.StringVarP(&options.proxyVersion, "proxy-version", "v", defaults.Global.Proxy.Image.Version, "Tag to be used for the Linkerd proxy images")
	flags.StringVar(&options.proxyImage, "proxy-image", defaults.Global.Proxy.Image.Name, "Linkerd proxy container image name")
	flags.StringVar(&options.initImage, "init-image", defaults.Global.ProxyInit.Image.Name, "Linkerd init container image name")
	flags.StringVar(&options.initImageVersion, "init-image-version", defaults.Global.ProxyInit.Image.Version, "Linkerd init container image version")
	flags.StringVar(&options.dockerRegistry, "registry", defaultDockerRegistry, "Docker registry to pull images from")
	flags.StringVar(&options.imagePullPolicy, "image-pull-policy", defaults.Global.ImagePullPolicy, "Docker image pull policy")
	flags.UintVar(&options.proxyInboundPort, "inbound-port", uint(defaults.Global.Proxy.Ports.Inbound), "Proxy port to use for inbound traffic")
	flags.UintVar(&options.proxyOutboundPort, "outbound-port", uint(defaults.Global.Proxy.Ports.Outbound), "Proxy port to use for outbound traffic")
	flags.StringSliceVar(&options.ignoreInboundPorts, "skip-inbound-ports", nil, "Ports and/or port ranges (inclusive) that should skip the proxy and send directly to the application")
	flags.StringSliceVar(&options.ignoreOutboundPorts, "skip-outbound-ports", nil, "Outbound ports and/or port ranges (inclusive) that should skip the proxy")
	flags.Int64Var(&options.proxyUID, "proxy-uid", defaults.Global.Proxy.UID, "Run the proxy under this user ID")
	flags.StringVar(&options.proxyLogLevel, "proxy-log-level", defaults.Global.Proxy.LogLevel, "Log level for the proxy")
	flags.UintVar(&options.proxyControlPort, "control-port", uint(defaults.Global.Proxy.Ports.Control), "Proxy port to use for control")
	flags.UintVar(&options.proxyAdminPort, "admin-port", uint(defaults.Global.Proxy.Ports.Admin), "Proxy port to serve metrics on")
	flags.StringVar(&options.proxyCPURequest, "proxy-cpu-request", defaults.Global.Proxy.Resources.CPU.Request, "Amount of CPU units that the proxy sidecar requests")
	flags.StringVar(&options.proxyMemoryRequest, "proxy-memory-request", defaults.Global.Proxy.Resources.Memory.Request, "Amount of Memory that the proxy sidecar requests")
	flags.StringVar(&options.proxyCPULimit, "proxy-cpu-limit", defaults.Global.Proxy.Resources.CPU.Limit, "Maximum amount of CPU units that the proxy sidecar can use")
	flags.StringVar(&options.proxyMemoryLimit, "proxy-memory-limit", defaults.Global.Proxy.Resources.Memory.Limit, "Maximum amount of Memory that the proxy sidecar can use")
	flags.BoolVar(&options.enableExternalProfiles, "enable-external-profiles", defaults.Global.Proxy.EnableExternalProfiles, "Enable service profiles for non-Kubernetes services")

	// Deprecated flags
	flags.StringVar(&options.proxyMemoryRequest, "proxy-memory", defaults.Global.Proxy.Resources.Memory.Request, "Amount of Memory that the proxy sidecar requests")
	flags.StringVar(&options.proxyCPURequest, "proxy-cpu", defaults.Global.Proxy.Resources.CPU.Request, "Amount of CPU units that the proxy sidecar requests")
	flags.MarkDeprecated("proxy-memory", "use --proxy-memory-request instead")
	flags.MarkDeprecated("proxy-cpu", "use --proxy-cpu-request instead")

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

func (options *proxyConfigOptions) validate() error {

	for _, network := range options.destinationGetNetworks {
		if _, _, err := net.ParseCIDR(network); err != nil {
			return fmt.Errorf("cannot parse destination get networks: %s", err)
		}
	}

	if options.disableIdentity && len(options.requireIdentityOnInboundPorts) > 0 {
		return errors.New("Identity must be enabled when  --require-identity-on-inbound-ports is specified")
	}

	if options.proxyVersion != "" && !alphaNumDashDot.MatchString(options.proxyVersion) {
		return fmt.Errorf("%s is not a valid version", options.proxyVersion)
	}

	if options.initImageVersion != "" && !alphaNumDashDot.MatchString(options.initImageVersion) {
		return fmt.Errorf("%s is not a valid version", options.initImageVersion)
	}

	if options.dockerRegistry != "" && !alphaNumDashDotSlashColon.MatchString(options.dockerRegistry) {
		return fmt.Errorf("%s is not a valid Docker registry. The url can contain only letters, numbers, dash, dot, slash and colon", options.dockerRegistry)
	}

	if options.imagePullPolicy != "" && options.imagePullPolicy != "Always" && options.imagePullPolicy != "IfNotPresent" && options.imagePullPolicy != "Never" {
		return fmt.Errorf("--image-pull-policy must be one of: Always, IfNotPresent, Never")
	}

	if options.proxyCPURequest != "" {
		if _, err := k8sResource.ParseQuantity(options.proxyCPURequest); err != nil {
			return fmt.Errorf("Invalid cpu request '%s' for --proxy-cpu-request flag", options.proxyCPURequest)
		}
	}

	if options.proxyMemoryRequest != "" {
		if _, err := k8sResource.ParseQuantity(options.proxyMemoryRequest); err != nil {
			return fmt.Errorf("Invalid memory request '%s' for --proxy-memory-request flag", options.proxyMemoryRequest)
		}
	}

	if options.proxyCPULimit != "" {
		cpuLimit, err := k8sResource.ParseQuantity(options.proxyCPULimit)
		if err != nil {
			return fmt.Errorf("Invalid cpu limit '%s' for --proxy-cpu-limit flag", options.proxyCPULimit)
		}
		if options.proxyCPURequest != "" {
			// Not checking for error because option proxyCPURequest was already validated
			if cpuRequest, _ := k8sResource.ParseQuantity(options.proxyCPURequest); cpuRequest.MilliValue() > cpuLimit.MilliValue() {
				return fmt.Errorf("The cpu limit '%s' cannot be lower than the cpu request '%s'", options.proxyCPULimit, options.proxyCPURequest)
			}
		}
	}

	if options.proxyMemoryLimit != "" {
		memoryLimit, err := k8sResource.ParseQuantity(options.proxyMemoryLimit)
		if err != nil {
			return fmt.Errorf("Invalid memory limit '%s' for --proxy-memory-limit flag", options.proxyMemoryLimit)
		}
		if options.proxyMemoryRequest != "" {
			// Not checking for error because option proxyMemoryRequest was already validated
			if memoryRequest, _ := k8sResource.ParseQuantity(options.proxyMemoryRequest); memoryRequest.Value() > memoryLimit.Value() {
				return fmt.Errorf("The memory limit '%s' cannot be lower than the memory request '%s'", options.proxyMemoryLimit, options.proxyMemoryRequest)
			}
		}
	}

	if options.proxyLogLevel != "" && !validProxyLogLevel.MatchString(options.proxyLogLevel) {
		return fmt.Errorf("\"%s\" is not a valid proxy log level - for allowed syntax check https://docs.rs/env_logger/0.6.0/env_logger/#enabling-logging",
			options.proxyLogLevel)
	}

	if err := validateRangeSlice(options.ignoreInboundPorts); err != nil {
		return err
	}

	if err := validateRangeSlice(options.ignoreOutboundPorts); err != nil {
		return err
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

		fmt.Println("Read addon config:")
		fmt.Println(string(addOnValuesRaw))

		err = yaml.Unmarshal(addOnValuesRaw, values)
		if err != nil {
			return err
		}

		fmt.Println("Updated values")
		y, _ := yaml.Marshal(values)
		fmt.Println(string(y))
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

func (options *installUpgradeOptions) applyToValues(k *k8s.KubernetesAPI, values *l5dcharts.Values) error {

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
	err := options.identityOptions.applyToValues(k, externallyManaged, values.Global.IdentityTrustDomain, values)
	if err != nil {
		return err
	}

	return nil
}

func (idopts *installIdentityOptions) applyToValues(k *k8s.KubernetesAPI, externallyManaged bool, trustDomain string, values *l5dcharts.Values) error {
	if idopts == nil {
		return nil
	}

	values.Identity.Issuer.ClockSkewAllowance = idopts.clockSkewAllowance.String()
	values.Identity.Issuer.IssuanceLifetime = idopts.issuanceLifetime.String()

	if externallyManaged {
		return idopts.readExternallyManaged(k, trustDomain, values)
	} else if idopts.trustPEMFile != "" && idopts.crtPEMFile != "" && idopts.keyPEMFile != "" {
		return idopts.readValues(trustDomain, values)
	}
	return nil
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
	fmt.Println("Defaults tree")
	fmt.Println(defaultsTree.String())
	valuesTree, err := tree.MarshalToTree(values)
	if err != nil {
		return nil, err
	}
	fmt.Println("Values tree")
	fmt.Println(valuesTree.String())
	return defaultsTree.Diff(valuesTree)
}

func (options *installUpgradeOptions) toOverrides(k *k8s.KubernetesAPI) (tree.Tree, error) {
	defaults, err := l5dcharts.NewValues(false)
	if err != nil {
		return nil, err
	}
	values, err := l5dcharts.NewValues(false)
	if err != nil {
		return nil, err
	}
	err = options.applyToValues(k, values)
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

/* Identity */

func (idopts *installIdentityOptions) issuerName(trustDomain string) string {
	return fmt.Sprintf("identity.%s.%s", controlPlaneNamespace, trustDomain)
}

func (idopts *installIdentityOptions) genValuesIfNecessary(values *l5dcharts.Values) error {
	if values.Identity.Issuer.Scheme == string(corev1.SecretTypeTLS) {
		// Externally managed.
		return nil
	}
	if values.Identity.Issuer.TLS.KeyPEM != "" || values.Identity.Issuer.TLS.CrtPEM != "" {
		// Certs already present.
		return nil
	}

	root, err := tls.GenerateRootCAWithDefaults(idopts.issuerName(values.Global.IdentityTrustDomain))
	if err != nil {
		return fmt.Errorf("failed to generate root certificate for identity: %s", err)
	}

	values.Identity.Issuer.Scheme = consts.IdentityIssuerSchemeLinkerd
	values.Identity.Issuer.CrtExpiry = root.Cred.Crt.Certificate.NotAfter
	values.Identity.Issuer.CrtExpiryAnnotation = k8s.IdentityIssuerExpiryAnnotation
	values.Identity.Issuer.TLS.KeyPEM = root.Cred.EncodePrivateKeyPEM()
	values.Identity.Issuer.TLS.CrtPEM = root.Cred.Crt.EncodeCertificatePEM()
	values.Global.IdentityTrustAnchorsPEM = root.Cred.Crt.EncodeCertificatePEM()

	return nil
}

func (idopts *installIdentityOptions) readExternallyManaged(k *k8s.KubernetesAPI, trustDomain string, values *l5dcharts.Values) error {

	externalIssuerData, err := issuercerts.FetchExternalIssuerData(k, controlPlaneNamespace)
	if err != nil {
		return err
	}
	_, err = externalIssuerData.VerifyAndBuildCreds(idopts.issuerName(trustDomain))
	if err != nil {
		return fmt.Errorf("failed to read CA from %s: %s", consts.IdentityIssuerSecretName, err)
	}

	values.Identity.Issuer.Scheme = string(corev1.SecretTypeTLS)
	values.Global.IdentityTrustAnchorsPEM = externalIssuerData.TrustAnchors

	return nil
}

// readValues attempts to read an issuer configuration from disk
// to produce an `installIdentityValues`.
//
// The identity options must have already been validated.
func (idopts *installIdentityOptions) readValues(trustDomain string, values *l5dcharts.Values) error {
	issuerData, err := issuercerts.LoadIssuerDataFromFiles(idopts.keyPEMFile, idopts.crtPEMFile, idopts.trustPEMFile)
	if err != nil {
		return err
	}

	creds, err := issuerData.VerifyAndBuildCreds(idopts.issuerName(trustDomain))
	if err != nil {
		return fmt.Errorf("failed to verify issuer certs stored on disk: %s", err)
	}

	values.Identity.Issuer.Scheme = consts.IdentityIssuerSchemeLinkerd
	values.Identity.Issuer.CrtExpiry = creds.Crt.Certificate.NotAfter
	values.Identity.Issuer.CrtExpiryAnnotation = k8s.IdentityIssuerExpiryAnnotation
	values.Identity.Issuer.TLS.CrtPEM = creds.EncodeCertificatePEM()
	values.Identity.Issuer.TLS.KeyPEM = creds.EncodePrivateKeyPEM()
	values.Global.IdentityTrustAnchorsPEM = issuerData.TrustAnchors

	return nil
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
