# keyswap

A simple CLI tool to automatically exchange SSH keys with remote servers.

## Features

- Auto-generates Ed25519 SSH keys if they don't exist
- Installs your public key on remote servers
- Sets proper file permissions automatically
- Removes duplicate keys from authorized_keys
- Follows Unix philosophy: silent on success, verbose on errors

## Installation

### Quick install (Linux/macOS)
```bash
curl -sSL https://raw.githubusercontent.com/bmntech-io/keyswap/main/install.sh | bash
```

### From releases
Download the latest binary from [releases](https://github.com/bmntech-io/keyswap/releases):

```bash
# Linux/macOS
curl -L -o keyswap https://github.com/bmntech-io/keyswap/releases/latest/download/keyswap-linux-amd64
chmod +x keyswap
sudo mv keyswap /usr/local/bin/
```

### From source
```bash
git clone https://github.com/bmntech-io/keyswap
cd keyswap
go build -o keyswap .
sudo mv keyswap /usr/local/bin/
```

### Using go install
```bash
go install github.com/bmntech-io/keyswap@latest
```

## Usage

```bash
# Basic usage
keyswap user@hostname

# Custom port
keyswap --port 2222 user@hostname

# Help
keyswap --help
```

## Examples

```bash
# Connect to a server with default SSH port
keyswap alice@192.168.1.100

# Connect to a server with custom port
keyswap --port 2222 bob@example.com

# Connect using hostname:port format
keyswap charlie@server.local:2222
```

## How it works

1. Checks for existing Ed25519 key pair in `~/.ssh/`
2. Generates new keys if they don't exist
3. Connects to remote server using password authentication
4. Creates `~/.ssh` directory on remote server if needed
5. Appends public key to `~/.ssh/authorized_keys`
6. Sets proper permissions (700 for .ssh, 600 for authorized_keys)
7. Removes duplicate keys

## Security Considerations

⚠️ **Current limitations:**
- Uses `InsecureIgnoreHostKey()` for host key verification (MVP only)
- Should implement proper known_hosts checking before production use

## Requirements

- Go 1.23 or later
- SSH access to target server with password authentication
- Unix-like system (Linux, macOS, WSL)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Related Tools

- `ssh-keygen` - Generate SSH keys
- `ssh-copy-id` - Copy keys to remote servers (one-directional)
- `ssh-agent` - Manage SSH keys in memory