package cmd

import (
	"encoding/json"
	"os"

	"github.com/kronos-project/pubkey-extract/client"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type Keyring struct {
	KeyBuffer []byte
	Keys      []client.Key
}

var (
	debug   bool
	binPath string

	rootCmd = &cobra.Command{
		Use: "pubkey-extract",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug {
				log.SetLevel(log.DebugLevel)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			g, err := client.Open(binPath)
			if err != nil {
				log.Fatalf("error opening game client: %v", err)
			}
			defer g.Close()

			keys, err := g.Keys()
			if err != nil {
				log.Error(err)
			}

			keyBuffer, err := g.KeyBuffer()
			if err != nil {
				log.Fatalf("error generating runtime buffer: %v", err)
			}

			json.NewEncoder(os.Stdout).Encode(Keyring{
				keyBuffer,
				keys,
			})
		},
	}
)

func init() {
	rootCmd.AddCommand(injectCmd)

	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "enable debug logging")
	rootCmd.PersistentFlags().StringVar(&binPath, "bin", "C:\\ProgramData\\KingsIsle Entertainment\\Wizard101\\Bin\\WizardGraphicalClient.exe", "path to WizardGraphicalClient binary")

	rootCmd.MarkPersistentFlagFilename("bin", "exe")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
