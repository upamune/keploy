package cli

import (
	"context"

	"github.com/spf13/cobra"
	"go.keploy.io/server/v3/config"
	loadSvc "go.keploy.io/server/v3/pkg/service/load"
	"go.keploy.io/server/v3/utils"
	"go.uber.org/zap"
)

func init() {
	Register("load", Load)
}

func Load(ctx context.Context, logger *zap.Logger, _ *config.Config, serviceFactory ServiceFactory, cmdConfigurator CmdConfigurator) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "load",
		Short:   "run a local load test from recorded HTTP test cases",
		Example: `keploy load --vus 10 --duration 30s --port 8080`,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return cmdConfigurator.Validate(ctx, cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, err := serviceFactory.GetService(ctx, cmd.Name())
			if err != nil {
				utils.LogError(logger, err, "failed to get service", zap.String("command", cmd.Name()))
				return nil
			}
			load, ok := svc.(loadSvc.Service)
			if !ok {
				utils.LogError(logger, nil, "service doesn't satisfy load service interface")
				return nil
			}
			if _, err := load.Run(ctx); err != nil {
				utils.LogError(logger, err, "failed to run load test")
			}
			return nil
		},
	}
	if err := cmdConfigurator.AddFlags(cmd); err != nil {
		utils.LogError(logger, err, "failed to add load flags")
		return nil
	}
	return cmd
}
