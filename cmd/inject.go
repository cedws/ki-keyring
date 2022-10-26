package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"os"

	"github.com/kronos-project/pubkey-extract/client"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	injectCmd = &cobra.Command{
		Use: "inject",
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

			for i := range keys {
				log.Debug("generating RSA key")
				keypair, _ := rsa.GenerateKey(rand.Reader, 2048)

				pub, _ := x509.MarshalPKIXPublicKey(keypair.Public())
				keys[i].Public = pub

				priv, _ := x509.MarshalPKCS8PrivateKey(keypair)
				keys[i].Private = priv
			}

			if err = g.WriteKeys(keys); err != nil {
				log.Fatalf("error writing keys: %v", err)
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
