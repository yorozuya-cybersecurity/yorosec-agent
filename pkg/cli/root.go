package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	Version = "0.0.1"
	rootCmd *cobra.Command
)

func init() {
	rootCmd = &cobra.Command{
		Use:   "yoro",
		Short: "SME self-service security agent",
		Long:  "Yorozuya SME security agent: run baseline scans, generate reports, and integrate with developer workflows.",
	}

	// Global flags
	rootCmd.PersistentFlags().StringP("output", "o", "./reports", "Output directory")
	_ = viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))

	// Environment variable support (YORO_OUTPUT, etc.)
	viper.SetEnvPrefix("YORO")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	// Subcommands
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newVersionCmd())
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
