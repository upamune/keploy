package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"go.keploy.io/server/v3/config"
	registrySvc "go.keploy.io/server/v3/pkg/service/registry"
	"go.keploy.io/server/v3/utils"
	"go.uber.org/zap"
)

func init() {
	Register("registry", Registry)
}

func Registry(ctx context.Context, logger *zap.Logger, _ *config.Config, serviceFactory ServiceFactory, cmdConfigurator CmdConfigurator) *cobra.Command {
	cmd := &cobra.Command{Use: "registry", Short: "manage local mock registry entries"}
	for _, name := range []string{"push", "pull", "list"} {
		sub := &cobra.Command{
			Use: name,
			PreRunE: func(cmd *cobra.Command, _ []string) error {
				return cmdConfigurator.Validate(ctx, cmd)
			},
			RunE: func(cmd *cobra.Command, _ []string) error {
				svc, err := serviceFactory.GetService(ctx, "registry")
				if err != nil {
					utils.LogError(logger, err, "failed to get registry service")
					return nil
				}
				reg, ok := svc.(registrySvc.Service)
				if !ok {
					utils.LogError(logger, nil, "service doesn't satisfy registry service interface")
					return nil
				}
				switch cmd.Name() {
				case "push":
					err = reg.Push(ctx)
				case "pull":
					err = reg.Pull(ctx)
				case "list":
					var names []string
					names, err = reg.List(ctx)
					for _, entry := range names {
						fmt.Fprintln(cmd.OutOrStdout(), entry)
					}
				}
				if err != nil {
					utils.LogError(logger, err, "registry command failed", zap.String("command", cmd.Name()))
				}
				return nil
			},
		}
		if err := cmdConfigurator.AddFlags(sub); err != nil {
			utils.LogError(logger, err, "failed to add registry flags")
			return nil
		}
		cmd.AddCommand(sub)
	}
	return cmd
}
