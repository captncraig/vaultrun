package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
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
)

func main() {

	log.Println(os.Args)
	if len(os.Args) < 2 {
		log.Fatal("USAGE: vaultrun cmd [args...]")
	}

	newEnviron := []string{}

	prefix := os.Getenv("VAULTRUN_DEFAULT_PATH")
	if prefix == "" {
		prefix = "secret"
	}
	absoluteSecrets := secretMap{}

	// collect what secrets to grab, copying anything else right over
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		k, v := parts[0], parts[1]

		isRel := strings.HasPrefix(v, relPrefix)
		isAbs := strings.HasPrefix(v, absPrefix)
		if isAbs || isRel {
			if isAbs {
				v = strings.TrimPrefix(v, absPrefix)
			} else {
				v = strings.TrimPrefix(v, relPrefix)
			}
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
			if isRel {
				secretName = prefix + "/" + secretName
			}
			absoluteSecrets[secretName] = append(absoluteSecrets[secretName], sts)
		} else if strings.HasPrefix(k, "VAULT_") || strings.HasPrefix(k, "VAULTRUN_") {
			// do not copy vault or vaultrun variables into child process
			// if needed, maybe make a special meta var for it
		} else {
			newEnviron = append(newEnviron, e)
		}
	}

	// create vault client
	conf := api.DefaultConfig()
	if err := conf.ReadEnvironment(); err != nil {
		log.Fatalf("Error creating vault config from environment: %s", err)
	}
	client, err := api.NewClient(conf)
	if err != nil {
		log.Fatalf("Error creating vault client: %s", err)
	}

	role := os.Getenv("VAULTRUN_KUBE_ROLE")
	mount := os.Getenv("VAULTRUN_KUBE_PATH")
	if role != "" || mount != "" {
		if role == "" || mount == "" {
			log.Fatalf("VAULTRUN_KUBE_ROLE and VAULTRUN_KUBE_PATH must both be set")
		}
		b64token, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			log.Fatalf("Couldn't load service account token from file: %s", err)
		}
		jwt, err := base64.StdEncoding.DecodeString(string(b64token))
		if err != nil {
			log.Fatalf("Invalid service account file %s. %s", string(b64token), err)
		}
		resp, err := client.Logical().Write(mount, map[string]interface{}{
			"role": role,
			"jwt":  string(jwt),
		})
		if err != nil {
			log.Fatalf("Error exchanging kube token for vault token: %s", err)
		}
		client.SetToken(resp.Auth.ClientToken)
	}

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

	var launch = execLaunch

	if runtime.GOOS == "windows" {
		launch = nonExecLaunch
	}

	if err = launch(newEnviron); err != nil {
		log.Fatalf("Error launching application: %s", err)
	}
}

func execLaunch(environ []string) error {
	cmdName := os.Args[1]
	fullPath, err := exec.LookPath(cmdName)
	if err != nil {
		return err
	}
	args := append([]string{fullPath}, os.Args[2:]...)
	syscall.Exec(fullPath, args, environ)
	return nil
}

func nonExecLaunch(environ []string) error {
	// windows fallback launcher. We really like unixy systems where we can `exec` to replace this process with the child one.
	// As a fallback, we launch the child process, pipe its IO to our own, and try to emulate its exit code.
	path := os.Args[1]
	args := os.Args[2:]
	log.Println(path, args)
	cmd := exec.Command(path, args...)
	cmd.Env = environ
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				code := status.ExitStatus()
				os.Exit(code)
			}
		}
	}
	return nil
}
