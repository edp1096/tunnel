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
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v3"
)

//go:embed sample_config.yaml
var sampleYAML string

type ProxyInfo struct {
	Name       string `yaml:"name"`
	Address    string `yaml:"address"`
	Port       string `yaml:"port"`
	Username   string `yaml:"username"`
	AuthMethod string `yaml:"authmethod"`
	Password   string `yaml:"password"`
	PrivateKey string `yaml:"privatekey"`
}

type TunnelInfo struct {
	Name         string `yaml:"name"`
	InternalAddr string `yaml:"internaladdr"`
	InternalPort string `yaml:"internalport"`
	LocalPort    string `yaml:"localport"`
}

type ProxyConfig struct {
	Proxy   ProxyInfo    `yaml:"proxy"`
	Tunnels []TunnelInfo `yaml:"tunnels"`
}

type Config struct {
	Servers []ProxyConfig `yaml:"servers"`
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

func getAuthMethod(proxy *ProxyInfo) (ssh.AuthMethod, error) {
	switch proxy.AuthMethod {
	case "password":
		return ssh.Password(proxy.Password), nil
	case "privatekey":
		if proxy.PrivateKey == "" {
			return nil, fmt.Errorf("privatekey is required")
		}

		pemPATH := proxy.PrivateKey
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
		sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
		if sshAuthSock == "" {
			return nil, fmt.Errorf("SSH_AUTH_SOCK environment variable not set")
		}

		conn, err := net.Dial("unix", sshAuthSock)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to SSH agent: %v", err)
		}

		agentClient := agent.NewClient(conn)
		return ssh.PublicKeysCallback(agentClient.Signers), nil
	default:
		return nil, fmt.Errorf("unknown auth method: %s", proxy.AuthMethod)
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

func startTunnel(sshClient *ssh.Client, proxyName string, tunnel TunnelInfo, maxTagLen int, maxLocalAddrLen int, wg *sync.WaitGroup) {
	defer wg.Done()

	tunnelName := tunnel.Name
	if tunnelName == "" {
		tunnelName = tunnel.InternalAddr
	}

	localAddr := "127.0.0.1:" + tunnel.LocalPort
	remoteAddr := net.JoinHostPort(tunnel.InternalAddr, tunnel.InternalPort)

	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Printf("[%s:%s] Local listen error: %v", proxyName, tunnelName, err)
		return
	}
	defer listener.Close()

	tag := fmt.Sprintf("[%s:%s]", proxyName, tunnelName)
	log.Printf("%-*s Tunnel established: %-*s -> %s", maxTagLen, tag, maxLocalAddrLen, localAddr, remoteAddr)

	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Printf("[%s:%s] Accept error: %v", proxyName, tunnelName, err)
			continue
		}

		go handleConnection(localConn, sshClient, remoteAddr)
	}
}

func startProxyServer(serverConfig ProxyConfig, wg *sync.WaitGroup) {
	defer wg.Done()

	proxy := serverConfig.Proxy
	proxyName := proxy.Name
	if proxyName == "" {
		proxyName = proxy.Address
	}

	if len(serverConfig.Tunnels) == 0 {
		log.Printf("[%s] No tunnels defined, skipping", proxyName)
		return
	}

	authMethod, err := getAuthMethod(&proxy)
	if err != nil {
		log.Printf("[%s] Auth method error: %v", proxyName, err)
		return
	}

	sshConfig := &ssh.ClientConfig{
		User:            proxy.Username,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	proxyAddr := net.JoinHostPort(proxy.Address, proxy.Port)
	sshClient, err := ssh.Dial("tcp", proxyAddr, sshConfig)
	if err != nil {
		log.Printf("[%s] SSH connection failed: %v", proxyName, err)
		return
	}
	defer sshClient.Close()

	// Calculate max tag length and max local address length for alignment
	maxTagLen := len(fmt.Sprintf("[%s]", proxyName))
	maxLocalAddrLen := 0
	for _, tunnel := range serverConfig.Tunnels {
		tunnelName := tunnel.Name
		if tunnelName == "" {
			tunnelName = tunnel.InternalAddr
		}
		tagLen := len(fmt.Sprintf("[%s:%s]", proxyName, tunnelName))
		if tagLen > maxTagLen {
			maxTagLen = tagLen
		}
		localAddr := "127.0.0.1:" + tunnel.LocalPort
		if len(localAddr) > maxLocalAddrLen {
			maxLocalAddrLen = len(localAddr)
		}
	}

	tag := fmt.Sprintf("[%s]", proxyName)
	log.Printf("%-*s SSH connected to: %s", maxTagLen, tag, proxyAddr)

	var tunnelWg sync.WaitGroup
	for _, tunnel := range serverConfig.Tunnels {
		tunnelWg.Add(1)
		go startTunnel(sshClient, proxyName, tunnel, maxTagLen, maxLocalAddrLen, &tunnelWg)
	}

	tunnelWg.Wait()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("* Run:        tunnel ./config.yaml")
		fmt.Println("* Get config: tunnel -getyaml")
		os.Exit(1)
	}

	if os.Args[1] == "-getyaml" {
		createYAML("sample_config.yaml")
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

	if len(config.Servers) == 0 {
		log.Fatalf("No servers defined in config")
	}

	var wg sync.WaitGroup
	for _, serverConfig := range config.Servers {
		wg.Add(1)
		go startProxyServer(serverConfig, &wg)
	}

	wg.Wait()
}
