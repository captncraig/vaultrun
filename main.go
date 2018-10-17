package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/hashicorp/vault/api"
)

type secretToStore struct {
	EnvName string
	Key     string
}
type secretMap map[string][]*secretToStore

const (
	msgFormat = "WARING: Environment '%s' looks like a vault replacement but is improperly formatted"

	relPrefix = "$v:"
	absPrefix = "$v!:"
	keySep    = "#"

	envDefaultPath = "VAULTRUN_DEFAULT_PATH"
)

func main() {
	newEnviron := []string{}

	prefix := "secret"
	absoluteSecrets := secretMap{}
	relativeSecrets := secretMap{}

	// collect what secrets to grab, copying anything else right over
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		k, v := parts[0], parts[1]
		parseSecret := func(prefix string, dest secretMap) {
			v = strings.TrimPrefix(v, prefix)
			vParts := strings.Split(v, keySep)
			if len(vParts) != 2 {
				log.Printf(msgFormat, e)
				newEnviron = append(newEnviron, e)
				return
			}
			sts := &secretToStore{
				EnvName: k,
				Key:     vParts[1],
			}
			secretName := vParts[0]
			dest[secretName] = append(dest[secretName], sts)
		}
		if k == envDefaultPath {
			prefix = v
		} else if strings.HasPrefix(v, absPrefix) {
			// absolute
			parseSecret(absPrefix, absoluteSecrets)
		} else if strings.HasPrefix(v, relPrefix) {
			// relative
			parseSecret(relPrefix, relativeSecrets)
		} else if strings.HasPrefix(k, "VAULT_") {
			// do not copy vault variables into child process
		} else {
			newEnviron = append(newEnviron, e)
		}
	}

	for k, vs := range relativeSecrets {
		for _, sts := range vs {
			absKey := prefix + "/" + k
			absoluteSecrets[absKey] = append(absoluteSecrets[absKey], sts)
		}
	}

	fmt.Println(absoluteSecrets)

	// create vault client
	conf := api.DefaultConfig()
	if err := conf.ReadEnvironment(); err != nil {
		log.Fatalf("Error creating vault client from environment: %s", err)
	}

	client, err := api.NewClient(conf)
	if err != nil {
		log.Fatalf("Error creating vault client: %s", err)
	}

	// TODO: check various auth methods.
	for path, replacements := range absoluteSecrets {
		secret, err := client.Logical().Read(path)
		if err != nil {
			log.Fatalf("Error reading secret %s: %s", path, err)
		}
		for _, r := range replacements {
			raw, ok := secret.Data[r.Key]
			if !ok {
				log.Fatalf("Secret %s has no key %s", path, r.Key)
			}
			val := fmt.Sprintf("%s=%s", r.EnvName, raw)
			newEnviron = append(newEnviron, val)
		}
	}

	for _, v := range newEnviron {
		fmt.Println(v)
	}

	var launch = syscall.Exec

	cmd := os.Args[1]
	args := os.Args[1:]

	if runtime.GOOS == "windows" {
		launch = nonExecLaunch
		args = args[1:]
	}

	launch(cmd, args, newEnviron)
}

func nonExecLaunch(path string, args []string, environ []string) error {
	cmd := exec.Command(path, args...)
	return nil
}
