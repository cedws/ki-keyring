package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cedws/pubkey-extract/keyring"
	"github.com/spf13/cobra"
)

var (
	binPath string
	pretty  bool
)

var rootCmd = &cobra.Command{
	Use: "pubkey-extract",
	Run: func(cmd *cobra.Command, args []string) {
		gameData, err := os.ReadFile(binPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		kr, err := keyring.Extract(gameData)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "    ")
		enc.Encode(kr)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&binPath, "bin", "C:\\ProgramData\\KingsIsle Entertainment\\Wizard101\\Bin\\WizardGraphicalClient.exe", "path to WizardGraphicalClient binary")
	rootCmd.MarkFlagFilename("bin", "exe")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
