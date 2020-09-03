package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	pb "github.com/linkerd/linkerd2/controller/gen/config"
	"github.com/linkerd/linkerd2/pkg/charts"
	l5dcharts "github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	"github.com/linkerd/linkerd2/pkg/healthcheck"
	"github.com/linkerd/linkerd2/pkg/issuercerts"
	"github.com/linkerd/linkerd2/pkg/k8s"
	consts "github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/tls"
	"github.com/linkerd/linkerd2/pkg/tree"
	"github.com/linkerd/linkerd2/pkg/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/helm/pkg/chartutil"
	"sigs.k8s.io/yaml"
)

type (
	allStageOptions struct {
		cniEnabled                  bool
		restrictDashboardPrivileges bool
		addOnConfig                 string
	}

	installOptions struct {
		clusterDomain          string
		identityExternalIssuer bool
		trustDomain            string
	}

	// installAndUpgradeOptions holds values for command line flags that apply
	// to the install
	// command. All fields in this struct should have corresponding flags added in
	// the newCmdInstall func later in this file. It also embeds proxyConfigOptions
	// in order to hold values for command line flags that apply to both inject and
	// install.
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

const (

	// addOnChartsPath is where the linkerd2 add-ons will be present
	addOnChartsPath = "add-ons"

	configStage       = "config"
	controlPlaneStage = "control-plane"

	defaultIdentityIssuanceLifetime   = 24 * time.Hour
	defaultIdentityClockSkewAllowance = 20 * time.Second

	helmDefaultChartName = "linkerd2"
	helmDefaultChartDir  = "linkerd2"

	errMsgCannotInitializeClient = `Unable to install the Linkerd control plane. Cannot connect to the Kubernetes cluster:

%s

You can use the --ignore-cluster flag if you just want to generate the installation config.`

	errMsgGlobalResourcesExist = `Unable to install the Linkerd control plane. It appears that there is an existing installation:

%s

If you are sure you'd like to have a fresh install, remove these resources with:

    linkerd install --ignore-cluster | kubectl delete -f -

Otherwise, you can use the --ignore-cluster flag to overwrite the existing global resources.
`

	errMsgLinkerdConfigResourceConflict = "Can't install the Linkerd control plane in the '%s' namespace. Reason: %s.\nIf this is expected, use the --ignore-cluster flag to continue the installation.\n"
	errMsgGlobalResourcesMissing        = "Can't install the Linkerd control plane in the '%s' namespace. The required Linkerd global resources are missing.\nIf this is expected, use the --skip-checks flag to continue the installation.\n"
)

var (
	templatesConfigStage = []string{
		"templates/namespace.yaml",
		"templates/identity-rbac.yaml",
		"templates/controller-rbac.yaml",
		"templates/destination-rbac.yaml",
		"templates/heartbeat-rbac.yaml",
		"templates/web-rbac.yaml",
		"templates/serviceprofile-crd.yaml",
		"templates/trafficsplit-crd.yaml",
		"templates/proxy-injector-rbac.yaml",
		"templates/sp-validator-rbac.yaml",
		"templates/tap-rbac.yaml",
		"templates/psp.yaml",
	}

	templatesControlPlaneStage = []string{
		"templates/_config.tpl",
		"templates/_helpers.tpl",
		"templates/config.yaml",
		"templates/identity.yaml",
		"templates/controller.yaml",
		"templates/destination.yaml",
		"templates/heartbeat.yaml",
		"templates/web.yaml",
		"templates/proxy-injector.yaml",
		"templates/sp-validator.yaml",
		"templates/tap.yaml",
		"templates/linkerd-config-addons.yaml",
	}

	ignoreCluster bool
)

// newCmdInstallConfig is a subcommand for `linkerd install config`
func newCmdInstallConfig(values *l5dcharts.Values) *cobra.Command {
	flags, options := makeAllStageFlags(values)

	cmd := &cobra.Command{
		Use:   "config [flags]",
		Args:  cobra.NoArgs,
		Short: "Output Kubernetes cluster-wide resources to install Linkerd",
		Long: `Output Kubernetes cluster-wide resources to install Linkerd.

This command provides Kubernetes configs necessary to install cluster-wide
resources for the Linkerd control plane. This command should be followed by
"linkerd install control-plane".`,
		Example: `  # Default install.
  linkerd install config | kubectl apply -f -

  # Install Linkerd into a non-default namespace.
  linkerd install config -l linkerdtest | kubectl apply -f -`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !ignoreCluster {
				if err := errAfterRunningChecks(options); err != nil {
					if healthcheck.IsCategoryError(err, healthcheck.KubernetesAPIChecks) {
						fmt.Fprintf(os.Stderr, errMsgCannotInitializeClient, err)
					} else {
						fmt.Fprintf(os.Stderr, errMsgGlobalResourcesExist, err)
					}
					os.Exit(1)
				}
			}

			options.applyToValues(values)

			return render(os.Stdout, values, configStage)
		},
	}

	cmd.Flags().AddFlagSet(flags)

	return cmd
}

// newCmdInstallControlPlane is a subcommand for `linkerd install control-plane`
func newCmdInstallControlPlane(values *l5dcharts.Values) *cobra.Command {
	var skipChecks bool

	allStageFlags, allStageOptions := makeAllStageFlags(values)
	installOnlyFlags, installOnlyOptions := makeInstallOnlyFlags(values)
	installUpgradeFlags, installUpgradeOptions, err := makeInstallUpgradeFlags(values)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd := &cobra.Command{
		Use:   "control-plane [flags]",
		Args:  cobra.NoArgs,
		Short: "Output Kubernetes control plane resources to install Linkerd",
		Long: `Output Kubernetes control plane resources to install Linkerd.

This command provides Kubernetes configs necessary to install the Linkerd
control plane. It should be run after "linkerd install config".`,
		Example: `  # Default install.
  linkerd install control-plane | kubectl apply -f -

  # Install Linkerd into a non-default namespace.
  linkerd install control-plane -l linkerdtest | kubectl apply -f -`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !skipChecks {
				// check if global resources exist to determine if the `install config`
				// stage succeeded
				if err := errAfterRunningChecks(allStageOptions); err == nil {
					if healthcheck.IsCategoryError(err, healthcheck.KubernetesAPIChecks) {
						fmt.Fprintf(os.Stderr, errMsgGlobalResourcesMissing, controlPlaneNamespace)
					}
					os.Exit(1)
				}
			}

			if !ignoreCluster {
				k8sAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 30*time.Second)
				if err != nil {
					return err
				}
				stored, err := loadStoredValues(k8sAPI)
				if err != nil {
					return err
				}
				if stored != nil {
					fmt.Fprintf(os.Stderr, errMsgLinkerdConfigResourceConflict, controlPlaneNamespace, "Secret/linkerd-config-overrides already exists")
					os.Exit(1)
				}
				err = errIfLinkerdConfigConfigMapExists()
				if err != nil {
					fmt.Fprintf(os.Stderr, errMsgLinkerdConfigResourceConflict, controlPlaneNamespace, err.Error())
					os.Exit(1)
				}
			}

			allStageOptions.applyToValues(values)
			installOnlyOptions.applyToValues(values)
			installUpgradeOptions.applyToValues(values)

			return render(os.Stdout, values, controlPlaneStage)
		},
	}

	cmd.Flags().AddFlagSet(allStageFlags)
	cmd.Flags().AddFlagSet(installOnlyFlags)
	cmd.Flags().AddFlagSet(installUpgradeFlags)

	return cmd
}

func newCmdInstall() *cobra.Command {
	options, err := newInstallOptionsWithDefaults()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}

	// The base flags are recorded separately so that they can be serialized into
	// the configuration in validateAndBuild.
	flags := options.recordableFlagSet()
	installOnlyFlags := options.installOnlyFlagSet()
	installPersistentFlags := options.installPersistentFlagSet()

	cmd := &cobra.Command{
		Use:   "install [flags]",
		Args:  cobra.NoArgs,
		Short: "Output Kubernetes configs to install Linkerd",
		Long: `Output Kubernetes configs to install Linkerd.

This command provides all Kubernetes configs necessary to install the Linkerd
control plane.`,
		Example: `  # Default install.
  linkerd install | kubectl apply -f -

  # Install Linkerd into a non-default namespace.
  linkerd install -l linkerdtest | kubectl apply -f -

  # Installation may also be broken up into two stages by user privilege, via
  # subcommands.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !options.ignoreCluster {
				if err := errAfterRunningChecks(options); err != nil {
					if healthcheck.IsCategoryError(err, healthcheck.KubernetesAPIChecks) {
						fmt.Fprintf(os.Stderr, errMsgCannotInitializeClient, err)
					} else {
						fmt.Fprintf(os.Stderr, errMsgGlobalResourcesExist, err)
					}
					os.Exit(1)
				}
			}

			return installRunE(options, "", flags)
		},
	}

	cmd.Flags().AddFlagSet(flags)

	// Some flags are not available during upgrade, etc.
	cmd.Flags().AddFlagSet(installOnlyFlags)
	cmd.Flags().AddFlagSet(installPersistentFlags)

	cmd.AddCommand(newCmdInstallConfig(options, flags))
	cmd.AddCommand(newCmdInstallControlPlane(options))

	return cmd
}

func installRunE(options *installOptions, stage string, flags *pflag.FlagSet) error {
	values, _, err := options.validateAndBuild(stage, flags)
	if err != nil {
		return err
	}

	return render(os.Stdout, values)
}

func (options *installOptions) validateAndBuild(stage string, flags *pflag.FlagSet) (*l5dcharts.Values, *pb.All, error) {
	if err := options.validate(); err != nil {
		return nil, nil, err
	}

	options.recordFlags(flags)

	identityValues, err := options.identityOptions.validateAndBuild()
	if err != nil {
		return nil, nil, err
	}
	return options.validateAndBuildWithIdentity(stage, identityValues)
}

func (options *installOptions) validateAndBuildWithIdentity(stage string, identityValues *identityWithAnchorsAndTrustDomain) (*l5dcharts.Values, *pb.All, error) {
	configs := options.configs(toIdentityContext(identityValues))

	values, err := options.buildValuesWithoutIdentity(configs)
	if err != nil {
		return nil, nil, err
	}
	values.Identity = identityValues.Identity
	values.Global.IdentityTrustAnchorsPEM = identityValues.TrustAnchorsPEM
	values.Global.IdentityTrustDomain = identityValues.TrustDomain
	values.Stage = stage

	// Update Configuration of Add-ons from config file
	err = options.UpdateAddOnValuesFromConfig(values)
	if err != nil {
		return nil, nil, err
	}

	if options.enableEndpointSlices {
		if err = validateEndpointSlicesFeature(); err != nil {
			return nil, nil, fmt.Errorf("--enableEndpointSlice=true not supported: %s", err)
		}
	}

	return values, configs, nil
}

func renderOverrides(values *l5dcharts.Values, namespace string) ([]byte, error) {
	defaults, err := l5dcharts.NewValues(false)
	if err != nil {
		return nil, err
	}
	values.Configs = l5dcharts.ConfigJSONs{}
	valuesTree, err := tree.MarshalToTree(values)
	if err != nil {
		return nil, err
	}
	defaultsTree, err := tree.MarshalToTree(defaults)
	if err != nil {
		return nil, err
	}

	overrides, err := defaultsTree.Diff(valuesTree)
	if err != nil {
		return nil, err
	}

	overridesBytes, err := yaml.Marshal(overrides)
	if err != nil {
		return nil, err
	}

	secret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "linkerd-config-overrides",
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"linkerd-config-overrides": overridesBytes,
		},
	}
	bytes, err := yaml.Marshal(secret)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// recordableFlagSet returns flags usable during install or upgrade.
func makeInstallUpgradeFlags(defaults *l5dcharts.Values) (*pflag.FlagSet, *installUpgradeOptions, error) {
	var options installUpgradeOptions
	flags := pflag.NewFlagSet("install", pflag.ExitOnError)
	flags.AddFlagSet(options.proxyConfigOptions.flagSet(pflag.ExitOnError))

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

// allStageFlagSet returns flags usable for single and multi-stage  installs and
// upgrades. For multi-stage installs, users must set these flags consistently
// across commands.
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

// installOnlyFlagSet includes flags that are only accessible at install-time
// and not at upgrade-time.
func installFlags(flags *pflag.FlagSet, defaults *l5dcharts.Values) installOptions {
	options := installOptions{}
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
	return options
}

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

func (options *installOptions) validate() error {
	if options.ignoreCluster && options.identityOptions.identityExternalIssuer {
		return errors.New("--ignore-cluster is not supported when --identity-external-issuer=true")
	}

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

	return nil
}

func validateEndpointSlicesFeature() error {
	k8sAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
	if err != nil {
		return err
	}

	return k8s.EndpointSliceAccess(k8sAPI)
}

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
	identity, err := options.identityOptions.validateAndBuild(externallyManaged, values.Global.IdentityTrustDomain)
	if err != nil {
		return err
	}
	values.Identity = identity.Identity
	values.Global.IdentityTrustAnchorsPEM = identity.TrustAnchorsPEM

	return nil
}

func render(w io.Writer, values *l5dcharts.Values, stage string) error {
	// Render raw values and create chart config
	rawValues, err := yaml.Marshal(values)
	if err != nil {
		return err
	}

	files := []*chartutil.BufferedFile{
		{Name: chartutil.ChartfileName},
	}

	addOns, err := l5dcharts.ParseAddOnValues(values)
	if err != nil {
		return err
	}

	// Initialize add-on sub-charts
	addOnCharts := make(map[string]*charts.Chart)
	for _, addOn := range addOns {
		addOnCharts[addOn.Name()] = &charts.Chart{
			Name:      addOn.Name(),
			Dir:       addOnChartsPath + "/" + addOn.Name(),
			Namespace: controlPlaneNamespace,
			RawValues: append(addOn.Values(), rawValues...),
			Files: []*chartutil.BufferedFile{
				{
					Name: chartutil.ChartfileName,
				},
				{
					Name: chartutil.ValuesfileName,
				},
			},
		}
	}

	if stage == "" || stage == configStage {
		for _, template := range templatesConfigStage {
			files = append(files,
				&chartutil.BufferedFile{Name: template},
			)
		}

		// Fill add-on's sub-charts with config templates
		for _, addOn := range addOns {
			addOnCharts[addOn.Name()].Files = append(addOnCharts[addOn.Name()].Files, addOn.ConfigStageTemplates()...)
		}
	}

	if stage == "" || stage == controlPlaneStage {
		for _, template := range templatesControlPlaneStage {
			files = append(files,
				&chartutil.BufferedFile{Name: template},
			)
		}

		// Fill add-on's sub-charts with control-plane templates
		for _, addOn := range addOns {
			addOnCharts[addOn.Name()].Files = append(addOnCharts[addOn.Name()].Files, addOn.ControlPlaneStageTemplates()...)
		}

	}

	// TODO refactor to use l5dcharts.LoadChart()
	chart := &charts.Chart{
		Name:      helmDefaultChartName,
		Dir:       helmDefaultChartDir,
		Namespace: controlPlaneNamespace,
		RawValues: rawValues,
		Files:     files,
	}
	buf, err := chart.Render()
	if err != nil {
		return err
	}

	for _, addon := range addOns {
		b, err := addOnCharts[addon.Name()].Render()
		if err != nil {
			return err
		}

		if _, err := buf.WriteString(b.String()); err != nil {
			return err
		}
	}

	overrides, err := renderOverrides(values, values.Global.Namespace)
	if err != nil {
		return err
	}
	buf.WriteString(yamlSep)
	buf.WriteString(string(overrides))

	_, err = w.Write(buf.Bytes())
	return err
}

func errAfterRunningChecks(options *allStageOptions) error {
	checks := []healthcheck.CategoryID{
		healthcheck.KubernetesAPIChecks,
		healthcheck.LinkerdPreInstallGlobalResourcesChecks,
	}
	hc := healthcheck.NewHealthChecker(checks, &healthcheck.Options{
		ControlPlaneNamespace: controlPlaneNamespace,
		KubeConfig:            kubeconfigPath,
		Impersonate:           impersonate,
		ImpersonateGroup:      impersonateGroup,
		KubeContext:           kubeContext,
		APIAddr:               apiAddr,
		CNIEnabled:            options.cniEnabled,
	})

	var k8sAPIError error
	errMsgs := []string{}
	hc.RunChecks(func(result *healthcheck.CheckResult) {
		if result.Err != nil {
			if ce, ok := result.Err.(*healthcheck.CategoryError); ok {
				if ce.Category == healthcheck.KubernetesAPIChecks {
					k8sAPIError = ce
				} else if re, ok := ce.Err.(*healthcheck.ResourceError); ok {
					// resource error, print in kind.group/name format
					for _, res := range re.Resources {
						errMsgs = append(errMsgs, res.String())
					}
				} else {
					// unknown category error, just print it
					errMsgs = append(errMsgs, result.Err.Error())
				}
			} else {
				// unknown error, just print it
				errMsgs = append(errMsgs, result.Err.Error())
			}
		}
	})

	// errors from the KubernetesAPIChecks category take precedence
	if k8sAPIError != nil {
		return k8sAPIError
	}

	if len(errMsgs) > 0 {
		return errors.New(strings.Join(errMsgs, "\n"))
	}

	return nil
}

func errIfLinkerdConfigConfigMapExists() error {
	kubeAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
	if err != nil {
		return err
	}

	_, err = kubeAPI.CoreV1().Namespaces().Get(controlPlaneNamespace, metav1.GetOptions{})
	if err != nil {
		return err
	}

	_, _, err = healthcheck.FetchLinkerdConfigMap(kubeAPI, controlPlaneNamespace)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return fmt.Errorf("'linkerd-config' config map already exists")
}

func checkFilesExist(files []string) error {
	for _, f := range files {
		stat, err := os.Stat(f)
		if err != nil {
			return fmt.Errorf("missing file: %s", err)
		}
		if stat.IsDir() {
			return fmt.Errorf("not a file: %s", f)
		}
	}
	return nil
}

func (idopts *installIdentityOptions) validate(externallyManaged bool) error {
	if idopts == nil {
		return nil
	}

	if idopts.trustDomain != "" {
		if errs := validation.IsDNS1123Subdomain(idopts.trustDomain); len(errs) > 0 {
			return fmt.Errorf("invalid trust domain '%s': %s", idopts.trustDomain, errs[0])
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

func (idopts *installIdentityOptions) validateAndBuild(externallyManaged bool, trustDomain string) (*identityWithAnchors, error) {
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
