package cmd

import (
	"fmt"
	"os"

	"github.com/cedws/ki-keyring/keyring"
	"github.com/spf13/cobra"
)

type output struct {
	Raw     []byte           `json:"raw"`
	Decoded *keyring.Keyring `json:"decoded"`
}

var binPath string

var rootCmd = &cobra.Command{
	Use: "ki-keyring",
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
