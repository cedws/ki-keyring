package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cedws/ki-keyring/keyring"
	"github.com/spf13/cobra"
)

var injectCmd = &cobra.Command{
	Use: "inject",
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
		if err := kr.Regenerate(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		newData, err := kr.Inject(gameData)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(binPath, newData, 0644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		raw, err := kr.MarshalBinary()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "    ")
		enc.Encode(output{raw, kr})
	},
}

func init() {
	rootCmd.AddCommand(injectCmd)
}
