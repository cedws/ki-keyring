package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cedws/ki-keyring/keyring"
	"github.com/spf13/cobra"
)

var ejectCmd = &cobra.Command{
	Use: "eject",
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
	rootCmd.AddCommand(ejectCmd)
}
