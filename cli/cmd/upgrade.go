package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/linkerd/linkerd2/cli/flag"
	charts "github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	l5dcharts "github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	"github.com/linkerd/linkerd2/pkg/healthcheck"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/tls"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const (
	controlPlaneMessage    = "Don't forget to run `linkerd upgrade control-plane`!"
	failMessage            = "For troubleshooting help, visit: https://linkerd.io/upgrade/#troubleshooting\n"
	trustRootChangeMessage = "Rotating the trust anchors will affect existing proxies\nSee https://linkerd.io/2/tasks/rotating_identity_certificates/ for more information"
)

type upgradeOptions struct {
	addOnOverwrite bool
	manifests      string
	force          bool
}

// newCmdUpgradeConfig is a subcommand for `linkerd upgrade config`
func newCmdUpgradeConfig(values *l5dcharts.Values, options *upgradeOptions) *cobra.Command {
	allStageFlags, allStageFlagSet := makeAllStageFlags(values)

	cmd := &cobra.Command{
		Use:   "config [flags]",
		Args:  cobra.NoArgs,
		Short: "Output Kubernetes cluster-wide resources to upgrade an existing Linkerd",
		Long: `Output Kubernetes cluster-wide resources to upgrade an existing Linkerd.

Note that this command should be followed by "linkerd upgrade control-plane".`,
		Example: `  # Default upgrade.
  linkerd upgrade config | kubectl apply -f -`,
		RunE: func(cmd *cobra.Command, args []string) error {

			k, err := k8sClient(options.manifests)
			if err != nil {
				return err
			}
			return upgradeRunE(k, options, allStageFlags, configStage)
		},
	}

	cmd.Flags().AddFlagSet(allStageFlagSet)

	return cmd
}

// newCmdUpgradeControlPlane is a subcommand for `linkerd upgrade control-plane`
func newCmdUpgradeControlPlane(values *l5dcharts.Values, options *upgradeOptions) *cobra.Command {
	allStageFlags, allStageFlagSet := makeAllStageFlags(values)
	installUpgradeFlags, installUpgradeFlagSet, err := makeInstallUpgradeFlags(values)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(1)
	}
	proxyFlags, proxyFlagSet := makeProxyFlags(values)

	flags := flattenFlags(allStageFlags, installUpgradeFlags, proxyFlags)

	cmd := &cobra.Command{
		Use:   "control-plane [flags]",
		Args:  cobra.NoArgs,
		Short: "Output Kubernetes control plane resources to upgrade an existing Linkerd",
		Long: `Output Kubernetes control plane resources to upgrade an existing Linkerd.

Note that the default flag values for this command come from the Linkerd control
plane. The default values displayed in the Flags section below only apply to the
install command. It should be run after "linkerd upgrade config".`,
		Example: `  # Default upgrade.
  linkerd upgrade control-plane | kubectl apply -f -`,
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := k8sClient(options.manifests)
			if err != nil {
				return err
			}
			return upgradeRunE(k, options, flags, controlPlaneStage)
		},
	}

	cmd.Flags().AddFlagSet(allStageFlagSet)
	cmd.Flags().AddFlagSet(installUpgradeFlagSet)
	cmd.Flags().AddFlagSet(proxyFlagSet)

	return cmd
}

func newCmdUpgrade() *cobra.Command {
	values, err := l5dcharts.NewValues(false)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(1)
	}

	allStageFlags, allStageFlagSet := makeAllStageFlags(values)
	installUpgradeFlags, installUpgradeFlagSet, err := makeInstallUpgradeFlags(values)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(1)
	}
	proxyFlags, proxyFlagSet := makeProxyFlags(values)
	flags := flattenFlags(allStageFlags, installUpgradeFlags, proxyFlags)

	options, upgradeFlagSet := makeUpgradeFlags()

	cmd := &cobra.Command{
		Use:   "upgrade [flags]",
		Args:  cobra.NoArgs,
		Short: "Output Kubernetes configs to upgrade an existing Linkerd control plane",
		Long: `Output Kubernetes configs to upgrade an existing Linkerd control plane.

Note that the default flag values for this command come from the Linkerd control
plane. The default values displayed in the Flags section below only apply to the
install command.`,

		Example: `  # Default upgrade.
  linkerd upgrade | kubectl apply --prune -l linkerd.io/control-plane-ns=linkerd -f -

  # Similar to install, upgrade may also be broken up into two stages, by user
  # privilege.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := k8sClient(options.manifests)
			if err != nil {
				return err
			}
			return upgradeRunE(k, options, flags, "")
		},
	}

	cmd.Flags().AddFlagSet(allStageFlagSet)
	cmd.Flags().AddFlagSet(installUpgradeFlagSet)
	cmd.Flags().AddFlagSet(proxyFlagSet)
	cmd.PersistentFlags().AddFlagSet(upgradeFlagSet)

	cmd.AddCommand(newCmdUpgradeConfig(values, options))
	cmd.AddCommand(newCmdUpgradeControlPlane(values, options))

	return cmd
}

func k8sClient(manifestsFile string) (*k8s.KubernetesAPI, error) {
	// We need a Kubernetes client to fetch configs and issuer secrets.
	var k *k8s.KubernetesAPI
	var err error
	if manifestsFile != "" {
		readers, err := read(manifestsFile)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse manifests from %s: %s", manifestsFile, err)
		}

		k, err = k8s.NewFakeAPIFromManifests(readers)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse Kubernetes objects from manifest %s: %s", manifestsFile, err)
		}
	} else {
		k, err = k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
		if err != nil {
			return nil, fmt.Errorf("Failed to create a kubernetes client: %s", err)
		}
	}
	return k, nil
}

func upgradeRunE(k *k8s.KubernetesAPI, options *upgradeOptions, flags []flag.Flag, stage string) error {

	buf, err := upgrade(k, options, flags, stage)
	if err != nil {
		return err
	}

	for _, flag := range flags {
		if flag.Name() == "identity-trust-anchors-file" && flag.IsSet() {
			fmt.Fprintf(os.Stderr, "\n%s %s\n\n", warnStatus, trustRootChangeMessage)
		}
	}
	if stage == configStage {
		fmt.Fprintf(os.Stderr, "%s\n\n", controlPlaneMessage)
	}

	buf.WriteTo(os.Stdout)

	return nil
}

func upgrade(k *k8s.KubernetesAPI, options *upgradeOptions, flags []flag.Flag, stage string) (bytes.Buffer, error) {
	values, err := loadStoredValues(k)
	if values == nil {
		values, err = loadStoredValuesLegacy(k, options)
		if err != nil {
			return bytes.Buffer{}, err
		}
	}

	if options.addOnOverwrite {
		values.Tracing = make(l5dcharts.Tracing)
		values.Grafana = make(l5dcharts.Grafana)
		values.Prometheus = make(l5dcharts.Prometheus)
	}

	err = flag.ApplySetFlags(values, flags)
	if err != nil {
		return bytes.Buffer{}, err
	}

	if values.Identity.Issuer.Scheme == string(corev1.SecretTypeTLS) {
		for _, flag := range flags {
			if (flag.Name() == "identity-issuer-certificate-file" || flag.Name() == "identity-issuer-key-file") && flag.IsSet() {
				return bytes.Buffer{}, errors.New("cannot update issuer certificates if you are using external cert management solution")
			}
		}
	}

	err = validateValues(k, values)
	if err != nil {
		return bytes.Buffer{}, err
	}
	if !options.force {
		err = ensureIssuerCertWorksWithAllProxies(k, values)
		if err != nil {
			return bytes.Buffer{}, err
		}
	}

	// rendering to a buffer and printing full contents of buffer after
	// render is complete, to ensure that okStatus prints separately
	var buf bytes.Buffer
	if err = render(&buf, values, stage); err != nil {
		upgradeErrorf("Could not render upgrade configuration: %s", err)
	}

	return buf, nil
}

func loadStoredValues(k *k8s.KubernetesAPI) (*charts.Values, error) {
	secret, err := k.CoreV1().Secrets(controlPlaneNamespace).Get("linkerd-config-overrides", metav1.GetOptions{})
	if kerrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	bytes, ok := secret.Data["linkerd-config-overrides"]
	if !ok {
		return nil, errors.New("secret/linkerd-config-overrides is missing linkerd-config-overrides data")
	}

	values, err := charts.NewValues(false)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(bytes, values)
	if err != nil {
		return nil, err
	}

	return values, nil
}

// upgradeErrorf prints the error message and quits the upgrade process
func upgradeErrorf(format string, a ...interface{}) {
	template := fmt.Sprintf("%s %s\n%s\n", failStatus, format, failMessage)
	fmt.Fprintf(os.Stderr, template, a...)
	os.Exit(1)
}

func ensureIssuerCertWorksWithAllProxies(k *k8s.KubernetesAPI, values *l5dcharts.Values) error {
	cred, err := tls.ValidateAndCreateCreds(
		values.Identity.Issuer.TLS.CrtPEM,
		values.Identity.Issuer.TLS.KeyPEM,
	)
	if err != nil {
		return err
	}

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
