package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

const (
	keyType     = "ed25519"
	keySize     = 256
	defaultPort = "22"
)

type Config struct {
	Host     string
	Port     string
	Username string
	KeyPath  string
}

func main() {
	var (
		port = flag.String("port", defaultPort, "SSH port")
		help = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		printUsage()
		return
	}

	args := flag.Args()
	if len(args) != 1 {
		printUsage()
		os.Exit(1)
	}

	config, err := parseTarget(args[0], *port)
	if err != nil {
		log.Fatalf("Error parsing target: %v", err)
	}

	if err := run(config); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func printUsage() {
	fmt.Println("keyswap - SSH key exchange tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  keyswap [options] user@hostname")
	fmt.Println("  keyswap --port 2222 user@hostname")
	fmt.Println()
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func parseTarget(target, port string) (*Config, error) {
	parts := strings.Split(target, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("target must be in format user@hostname")
	}

	username := strings.TrimSpace(parts[0])
	host := strings.TrimSpace(parts[1])

	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	if host == "" {
		return nil, fmt.Errorf("hostname cannot be empty")
	}

	// Handle hostname:port format
	if strings.Contains(host, ":") {
		hostParts := strings.Split(host, ":")
		if len(hostParts) != 2 {
			return nil, fmt.Errorf("invalid hostname:port format")
		}
		host = strings.TrimSpace(hostParts[0])
		port = strings.TrimSpace(hostParts[1])

		if host == "" {
			return nil, fmt.Errorf("hostname cannot be empty")
		}

		if port == "" {
			return nil, fmt.Errorf("port cannot be empty")
		}
	}

	usr, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("unable to get current user: %w", err)
	}

	return &Config{
		Host:     host,
		Port:     port,
		Username: username,
		KeyPath:  filepath.Join(usr.HomeDir, ".ssh"),
	}, nil
}

func run(config *Config) error {
	// Ensure local .ssh directory exists
	if err := ensureSSHDir(config.KeyPath); err != nil {
		return fmt.Errorf("failed to setup .ssh directory: %w", err)
	}

	// Generate key if it doesn't exist
	privateKeyPath := filepath.Join(config.KeyPath, "id_ed25519")
	publicKeyPath := privateKeyPath + ".pub"

	if !fileExists(privateKeyPath) {
		if err := generateKeyPair(privateKeyPath, publicKeyPath); err != nil {
			return fmt.Errorf("failed to generate key pair: %w", err)
		}
	}

	// Read public key
	pubKeyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	// Connect and install key
	if err := installPublicKey(config, string(pubKeyData)); err != nil {
		return fmt.Errorf("failed to install public key: %w", err)
	}

	return nil
}

func ensureSSHDir(sshPath string) error {
	if err := os.MkdirAll(sshPath, 0700); err != nil {
		return err
	}
	return os.Chmod(sshPath, 0700)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func generateKeyPair(privateKeyPath, publicKeyPath string) error {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Convert private key to OpenSSH format
	privKeyBytes, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Write private key
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(privKeyBytes), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Convert public key to SSH format
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create SSH public key: %w", err)
	}

	// Write public key
	authorizedKey := ssh.MarshalAuthorizedKey(sshPublicKey)
	if err := os.WriteFile(publicKeyPath, authorizedKey, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

func installPublicKey(config *Config, pubKey string) error {
	// Get password for SSH connection
	fmt.Printf("Enter password for %s@%s: ", config.Username, config.Host)
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println() // New line after password input

	// Create SSH client config
	sshConfig := &ssh.ClientConfig{
		User: config.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(string(password)),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // MVP: accept any host key
	}

	// Connect to SSH server
	addr := net.JoinHostPort(config.Host, config.Port)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer client.Close()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Commands to setup authorized_keys
	commands := []string{
		"mkdir -p ~/.ssh",
		"chmod 700 ~/.ssh",
		fmt.Sprintf("echo '%s' >> ~/.ssh/authorized_keys", strings.TrimSpace(pubKey)),
		"chmod 600 ~/.ssh/authorized_keys",
		"sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys", // Remove duplicates
	}

	command := strings.Join(commands, " && ")

	if err := session.Run(command); err != nil {
		return fmt.Errorf("failed to install key: %w", err)
	}

	return nil
}

func getSSHAgent() ssh.AuthMethod {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	}
	return nil
}

func loadPrivateKey(keyPath string) (ssh.AuthMethod, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(signer), nil
}
