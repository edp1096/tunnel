package main // import "tunnel"

import (
	_ "embed"
	"path/filepath"
	"strings"

	"fmt"
	"log"
	"os"

	"github.com/elliotchance/sshtunnel"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

//go:embed config.yaml
var sampleYAML string

type ProxyInfo struct {
	Address    string `yaml:"address"`
	Port       string `yaml:"port"`
	Username   string `yaml:"username"`
	AuthMethod string `yaml:"authmethod"`
	Password   string `yaml:"password"`
	PrivateKey string `yaml:"privatekey"`
}

type InternalServerInfo struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type Config struct {
	Proxy          ProxyInfo          `yaml:"proxyserver"`
	InternalServer InternalServerInfo `yaml:"internalserver"`
	LocalPort      string             `yaml:"localport"`
}

func createYAML(iniPath string) {
	if _, err := os.Stat(iniPath); !os.IsNotExist(err) {
		fmt.Printf("File %s already exists.\n", iniPath)
		os.Exit(1)
	}

	f, err := os.Create(iniPath)
	if err != nil {
		log.Fatalln("Create INI: ", err)
	}
	defer f.Close()

	_, err = f.WriteString(sampleYAML)
	if err != nil {
		log.Fatalln("Create INI: ", err)
	}

	fmt.Println(iniPath + " is created")
	fmt.Println("Please modify " + iniPath + " then run again")

	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("* Run:        tunnel ./config.yaml")
		fmt.Println("* Get config: tunnel -getyaml")
		os.Exit(1)
	}

	if os.Args[1] == "-getyaml" {
		createYAML("config_sample.yaml")
	}

	configFile := os.Args[1]

	data, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Println("Error when " + configFile + " reading")
		os.Exit(1)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		fmt.Println("Error when " + configFile + " parsing")
		os.Exit(1)
	}

	proxyADDR := config.Proxy.Username + "@" + config.Proxy.Address + ":" + config.Proxy.Port
	proxyPW := config.Proxy.Password
	inADDR := config.InternalServer.Address + ":" + config.InternalServer.Port
	authMETHOD := config.Proxy.AuthMethod

	var authWAY ssh.AuthMethod
	switch authMETHOD {
	case "password":
		authWAY = ssh.Password(proxyPW)
	case "privatekey":
		if config.Proxy.PrivateKey == "" {
			fmt.Println("privatekey is required")
			os.Exit(1)
		}

		pemPATH := config.Proxy.PrivateKey
		if !filepath.IsAbs(pemPATH) {
			if strings.HasPrefix(pemPATH, "~/") || strings.HasPrefix(pemPATH, "~\\") {
				dirname, _ := os.UserHomeDir()
				pemPATH = filepath.Join(dirname, pemPATH[2:])
			}

			pemPATH, _ = filepath.Abs(pemPATH)
		}
		authWAY = sshtunnel.PrivateKeyFile(pemPATH)
	case "agent":
		authWAY = sshtunnel.SSHAgent()
	}

	tunnel, err := sshtunnel.NewSSHTunnel(proxyADDR, authWAY, inADDR, config.LocalPort)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	tunnel.Log = log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds)
	tunnel.Start()
}
