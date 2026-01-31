package main

import (
	_ "embed"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

//go:embed sample_config.yaml
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

func getAuthMethod(config *Config) (ssh.AuthMethod, error) {
	switch config.Proxy.AuthMethod {
	case "password":
		return ssh.Password(config.Proxy.Password), nil
	case "privatekey":
		if config.Proxy.PrivateKey == "" {
			return nil, fmt.Errorf("privatekey is required")
		}

		pemPATH := config.Proxy.PrivateKey
		if !filepath.IsAbs(pemPATH) {
			if strings.HasPrefix(pemPATH, "~/") || strings.HasPrefix(pemPATH, "~\\") {
				dirname, _ := os.UserHomeDir()
				pemPATH = filepath.Join(dirname, pemPATH[2:])
			}
			pemPATH, _ = filepath.Abs(pemPATH)
		}

		key, err := os.ReadFile(pemPATH)
		if err != nil {
			return nil, fmt.Errorf("unable to read private key: %v", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %v", err)
		}

		return ssh.PublicKeys(signer), nil
	case "agent":
		return nil, fmt.Errorf("agent auth not implemented in this version")
	default:
		return nil, fmt.Errorf("unknown auth method: %s", config.Proxy.AuthMethod)
	}
}

func handleConnection(localConn net.Conn, sshClient *ssh.Client, remoteAddr string) {
	remoteConn, err := sshClient.Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("Remote dial error: %v", err)
		localConn.Close()
		return
	}

	copyConn := func(writer, reader net.Conn) {
		defer writer.Close()
		defer reader.Close()
		io.Copy(writer, reader)
	}

	go copyConn(localConn, remoteConn)
	go copyConn(remoteConn, localConn)
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

	authMethod, err := getAuthMethod(&config)
	if err != nil {
		log.Fatalf("Auth method error: %v", err)
	}

	sshConfig := &ssh.ClientConfig{
		User: config.Proxy.Username,
		Auth: []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	proxyAddr := config.Proxy.Address + ":" + config.Proxy.Port
	sshClient, err := ssh.Dial("tcp", proxyAddr, sshConfig)
	if err != nil {
		log.Fatalf("SSH connection failed: %v", err)
	}
	defer sshClient.Close()

	localAddr := "127.0.0.1:" + config.LocalPort
	remoteAddr := config.InternalServer.Address + ":" + config.InternalServer.Port

	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("Local listen error: %v", err)
	}
	defer listener.Close()

	log.Printf("Tunnel established: %s -> %s -> %s", localAddr, proxyAddr, remoteAddr)

	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleConnection(localConn, sshClient, remoteAddr)
	}
}