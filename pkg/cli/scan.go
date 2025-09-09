package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/yorozuya-cybersecurity/yorosec-agent/internal/scanners"
	"github.com/yorozuya-cybersecurity/yorosec-agent/internal/schema"
	"github.com/yorozuya-cybersecurity/yorosec-agent/pkg/utils"
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a baseline security scan (skeleton)",
		RunE: func(cmd *cobra.Command, args []string) error {
			target := viper.GetString("target")
			if target == "" {
				return errors.New("please provide --target")
			}
			attest := viper.GetString("attest")
			if attest == "" {
				return errors.New("please provide --attest to confirm authorization")
			}

			fmt.Printf("🚀 Running nuclei scan for %s\n", target)
			findings, err := scanners.RunNuclei(target)
			if err != nil {
				return err
			}

			res := schema.ScanResult{
				Target:    target,
				Timestamp: time.Now(),
				Findings:  findings,
			}

			outDir := viper.GetString("output")
			file, err := utils.SaveResult(res, outDir)
			if err != nil {
				return err
			}

			fmt.Printf("✅ Scan complete. Results saved to %s\n", file)
			fmt.Printf("   Total findings: %d\n", len(findings))
			return nil
		},
	}

	cmd.Flags().String("target", "", "Target to scan (URL or domain)")
	cmd.Flags().String("attest", "", "Authorization statement (e.g., 'I am authorized to test this target')")
	_ = viper.BindPFlag("target", cmd.Flags().Lookup("target"))
	_ = viper.BindPFlag("attest", cmd.Flags().Lookup("attest"))

	return cmd
}
