package network

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/Team254/cheesy-arena/model"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func unusedSwitchPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	return port
}

type switchSSHResult struct {
	commands []string
	err      error
}

func mockIOSSwitch(t *testing.T, config *ssh.ServerConfig, privileged bool, rejectCommand string, connections int) (int, <-chan switchSSHResult) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	results := make(chan switchSSHResult, 1)
	go func() {
		var result switchSSHResult
		defer func() { results <- result }()
		for i := 0; i < connections; i++ {
			conn, err := listener.Accept()
			if err != nil {
				result.err = err
				return
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			defer conn.Close()
			server, channels, requests, err := ssh.NewServerConn(conn, config)
			if err != nil {
				result.err = err
				return
			}
			defer server.Close()
			go ssh.DiscardRequests(requests)
			channelRequest, ok := <-channels
			if !ok {
				result.err = fmt.Errorf("client closed before opening a session")
				return
			}
			channel, requests, err := channelRequest.Accept()
			if err != nil {
				result.err = err
				return
			}
			for request := range requests {
				request.Reply(request.Type == "pty-req" || request.Type == "shell", nil)
				if request.Type == "shell" {
					break
				}
			}
			commands, err := serveIOSCLI(channel, privileged, rejectCommand)
			result.commands = append(result.commands, commands...)
			channel.Close()
			if err != nil {
				result.err = err
				return
			}
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, results
}

func switchServerConfig() *ssh.ServerConfig {
	return &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() != "fieldadmin" || string(password) != "password" {
				return nil, fmt.Errorf("incorrect credentials")
			}
			return nil, nil
		},
	}
}

func serveIOSCLI(conn io.ReadWriter, privileged bool, rejectCommand string) ([]string, error) {
	prompt := "ChezySwitch>"
	if privileged {
		prompt = "ChezySwitch#"
	}
	if _, err := fmt.Fprint(conn, prompt); err != nil {
		return nil, err
	}
	var commands []string
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return commands, err
		}
		line = strings.TrimSpace(line)
		commands = append(commands, line)
		if line == "exit" {
			return commands, nil
		}
		switch line {
		case "enable":
			prompt = "Password:"
		case "password":
			if prompt != "Password:" {
				return commands, fmt.Errorf("unsolicited enable password")
			}
			prompt = "ChezySwitch#"
		case "config terminal":
			prompt = "ChezySwitch(config)#"
		case "end":
			prompt = "ChezySwitch#"
		}
		response := "\r\n" + prompt
		if line == rejectCommand {
			response = "\r\n% Invalid input detected at '^' marker.\r\n" + prompt
		}
		if _, err := fmt.Fprint(conn, response); err != nil {
			return commands, err
		}
		if line == rejectCommand {
			return commands, nil
		}
	}
}

func TestSwitchSSHAlgorithms(t *testing.T) {
	for _, kex := range []string{
		"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha256", "curve25519-sha256",
	} {
		for _, cipher := range []string{"aes128-gcm@openssh.com", "aes128-ctr", "aes128-cbc"} {
			t.Run(kex+"/"+cipher, func(t *testing.T) {
				config := switchServerConfig()
				config.KeyExchanges = []string{kex}
				config.Ciphers = []string{cipher}
				sw := NewSwitch("127.0.0.1", "password")
				sw.SetUsername("fieldadmin")
				port, results := mockIOSSwitch(t, config, true, "", 1)
				sw.sshPort = port
				output, err := sw.runConfigCommand("interface Vlan10\nno ip address\n")
				require.NoError(t, err)
				require.Contains(t, output, "ChezySwitch(config)#")
				result := <-results
				require.NoError(t, result.err)
				require.Equal(t, []string{
					"terminal length 0", "config terminal", "interface Vlan10", "no ip address", "end", "exit",
				}, result.commands)
			})
		}
	}
}

func TestSwitchSSHConfigureTeams(t *testing.T) {
	sw := NewSwitch("127.0.0.1", "password")
	sw.SetUsername("fieldadmin")
	sw.configPauseDuration = 0
	sw.configBackoffDuration = 0
	port, results := mockIOSSwitch(t, switchServerConfig(), false, "", 2)
	sw.sshPort = port
	require.NoError(t, sw.ConfigureTeamEthernet([6]*model.Team{{Id: 537}}))
	require.Equal(t, "ACTIVE", sw.Status)
	result := <-results
	require.NoError(t, result.err)
	require.Equal(t, 2, strings.Count(strings.Join(result.commands, "\n"), "enable\npassword\n"))
	require.Contains(t, result.commands, "no ip dhcp pool dhcp60")
	require.Contains(t, result.commands, "network 10.5.37.0 255.255.255.0")
	require.Contains(t, result.commands, "ip address 10.5.37.4 255.255.255.0")
}

func TestSwitchSSHCommandRejected(t *testing.T) {
	sw := NewSwitch("127.0.0.1", "password")
	sw.SetUsername("fieldadmin")
	port, results := mockIOSSwitch(t, switchServerConfig(), true, "no ip address", 1)
	sw.sshPort = port
	require.ErrorContains(t, sw.ConfigureTeamEthernet([6]*model.Team{}), "switch rejected command")
	require.Equal(t, "ERROR", sw.Status)
	require.NoError(t, (<-results).err)
}

func TestSwitchSSHFailureDoesNotFallBack(t *testing.T) {
	for _, failure := range []string{"authentication", "negotiation"} {
		t.Run(failure, func(t *testing.T) {
			config := switchServerConfig()
			sw := NewSwitch("127.0.0.1", "wrong password")
			sw.SetUsername("fieldadmin")
			if failure == "negotiation" {
				config.Ciphers = []string{ssh.CipherAES256CTR}
			}
			port, results := mockIOSSwitch(t, config, true, "", 1)
			sw.sshPort = port
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			sw.port = listener.Addr().(*net.TCPAddr).Port
			_, err = sw.runCommand("show version\n")
			require.ErrorContains(t, err, "Telnet fallback disabled")
			require.Error(t, (<-results).err)
			require.NoError(t, listener.(*net.TCPListener).SetDeadline(time.Now().Add(20*time.Millisecond)))
			conn, err := listener.Accept()
			if conn != nil {
				conn.Close()
				t.Fatal("SSH failure attempted plaintext Telnet")
			}
			require.Error(t, err)
		})
	}
}

func TestSwitchTelnetLocalLogin(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	results := make(chan switchSSHResult, 1)
	go func() {
		var result switchSSHResult
		defer func() { results <- result }()
		conn, err := listener.Accept()
		if err != nil {
			result.err = err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(conn, "\xff\xfb\x01Username:")
		reply := make([]byte, 3)
		_, result.err = io.ReadFull(conn, reply)
		if result.err != nil {
			return
		}
		if !bytes.Equal(reply, []byte{255, 254, 1}) {
			result.err = fmt.Errorf("incorrect Telnet negotiation reply: %v", reply)
			return
		}
		reader := bufio.NewReader(conn)
		for _, credential := range []string{"fieldadmin", "password"} {
			line, err := reader.ReadString('\n')
			if err != nil || strings.TrimSpace(line) != credential {
				result.err = fmt.Errorf("incorrect Telnet login: %w", err)
				return
			}
			if credential == "fieldadmin" {
				fmt.Fprint(conn, "\r\nPassword:")
			}
		}
		result.commands, result.err = serveIOSCLI(conn, false, "")
	}()
	sw := NewSwitch("127.0.0.1", "password")
	sw.SetUsername("fieldadmin")
	sw.sshPort = unusedSwitchPort(t)
	sw.port = listener.Addr().(*net.TCPAddr).Port
	_, err = sw.runConfigCommand("interface Vlan10\nno ip address\n")
	require.NoError(t, err)
	result := <-results
	require.NoError(t, result.err)
	require.Equal(t, []string{
		"enable", "password", "terminal length 0", "config terminal", "interface Vlan10", "no ip address", "end", "exit",
	}, result.commands)
}

func TestSwitchInteractiveFailures(t *testing.T) {
	for _, response := range []string{
		"ChezySwitch>\nPassword:\nPassword:",
		"ChezySwitch#\n% Invalid input detected\r\nChezySwitch#",
		"ChezySwitch#\n",
	} {
		var input bytes.Buffer
		_, err := NewSwitch("", "password").runInteractiveCommand(bufio.NewReader(strings.NewReader(response)), &input, "show version")
		require.Error(t, err)
	}
}
