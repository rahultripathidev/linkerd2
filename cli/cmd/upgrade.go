package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	charts "github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	l5dcharts "github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/tree"
	"github.com/spf13/cobra"
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
	allStageFlags, allStageOptions := makeAllStageFlags(values)

	cmd := &cobra.Command{
		Use:   "config [flags]",
		Args:  cobra.NoArgs,
		Short: "Output Kubernetes cluster-wide resources to upgrade an existing Linkerd",
		Long: `Output Kubernetes cluster-wide resources to upgrade an existing Linkerd.

Note that this command should be followed by "linkerd upgrade control-plane".`,
		Example: `  # Default upgrade.
  linkerd upgrade config | kubectl apply -f -`,
		RunE: func(cmd *cobra.Command, args []string) error {
			overrides, err := allStageOptions.toOverrides()
			if err != nil {
				return err
			}
			return upgradeRunE(options, overrides, configStage)
		},
	}

	cmd.Flags().AddFlagSet(allStageFlags)

	return cmd
}

// newCmdUpgradeControlPlane is a subcommand for `linkerd upgrade control-plane`
func newCmdUpgradeControlPlane(values *l5dcharts.Values, options *upgradeOptions) *cobra.Command {
	allStageFlags, allStageOptions := makeAllStageFlags(values)
	installUpgradeFlags, installUpgradeOptions, err := makeInstallUpgradeFlags(values)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(1)
	}

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
			overrides, err := allStageOptions.toOverrides()
			if err != nil {
				return err
			}
			upgradeOverrides, err := installUpgradeOptions.toOverrides()
			if err != nil {
				return err
			}
			err = overrides.Merge(upgradeOverrides)
			if err != nil {
				return err
			}
			return upgradeRunE(options, overrides, controlPlaneStage)
		},
	}

	cmd.Flags().AddFlagSet(allStageFlags)
	cmd.Flags().AddFlagSet(installUpgradeFlags)

	return cmd
}

func newCmdUpgrade() *cobra.Command {
	values, err := l5dcharts.NewValues(false)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(1)
	}

	allStageFlags, allStageOptions := makeAllStageFlags(values)
	installUpgradeFlags, installUpgradeOptions, err := makeInstallUpgradeFlags(values)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(1)
	}
	flags, options := makeUpgradeFlags()

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
			overrides, err := allStageOptions.toOverrides()
			if err != nil {
				return err
			}
			upgradeOverrides, err := installUpgradeOptions.toOverrides()
			if err != nil {
				return err
			}
			err = overrides.Merge(upgradeOverrides)
			if err != nil {
				return err
			}
			return upgradeRunE(options, overrides, "")
		},
	}

	cmd.Flags().AddFlagSet(allStageFlags)
	cmd.Flags().AddFlagSet(installUpgradeFlags)
	cmd.PersistentFlags().AddFlagSet(flags)

	cmd.AddCommand(newCmdUpgradeConfig(values, options))
	cmd.AddCommand(newCmdUpgradeControlPlane(values, options))

	return cmd
}

func k8sClient(options *upgradeOptions) (*k8s.KubernetesAPI, error) {
	// We need a Kubernetes client to fetch configs and issuer secrets.
	var k *k8s.KubernetesAPI
	var err error
	if options.manifests != "" {
		readers, err := read(options.manifests)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse manifests from %s: %s", options.manifests, err)
		}

		k, err = k8s.NewFakeAPIFromManifests(readers)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse Kubernetes objects from manifest %s: %s", options.manifests, err)
		}
	} else {
		k, err = k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
		if err != nil {
			return nil, fmt.Errorf("Failed to create a kubernetes client: %s", err)
		}
	}
	return k, nil
}

func upgradeRunE(options *upgradeOptions, upgradeOverrides tree.Tree, stage string) error {

	k, err := k8sClient(options)
	if err != nil {
		return err
	}

	values, err := loadStoredValues(k)
	if values == nil {
		values, err = loadStoredValuesLegacy(k, options)
		if err != nil {
			return err
		}
	}

	err = upgradeOverrides.MarshalOnto(values)
	if err != nil {
		return err
	}

	// rendering to a buffer and printing full contents of buffer after
	// render is complete, to ensure that okStatus prints separately
	var buf bytes.Buffer
	if err = render(&buf, values, stage); err != nil {
		upgradeErrorf("Could not render upgrade configuration: %s", err)
	}

	if _, ok := upgradeOverrides.Get([]string{"global", "identityTrustAnchorsPEM"}); ok {
		fmt.Fprintf(os.Stderr, "\n%s %s\n\n", warnStatus, trustRootChangeMessage)
	}
	if stage == configStage {
		fmt.Fprintf(os.Stderr, "%s\n\n", controlPlaneMessage)
	}

	buf.WriteTo(os.Stdout)

	return nil
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
