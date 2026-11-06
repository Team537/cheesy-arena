// Copyright 2014 Team 254. All Rights Reserved.
// Author: pat@patfairbank.com (Patrick Fairbank)
//
// Methods for configuring Cisco IOS and IOS XE switches for team VLANs.

package network

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/Team254/cheesy-arena/model"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	switchConfigBackoffDurationSec = 5
	switchConfigPauseDurationSec   = 2
	switchTeamGatewayAddress       = 4
	switchTelnetPort               = 23
	switchSSHPort                  = 22
	switchConnectTimeout           = 5 * time.Second
	switchCommandTimeout           = 30 * time.Second
)

const (
	red1Vlan  = 10
	red2Vlan  = 20
	red3Vlan  = 30
	blue1Vlan = 40
	blue2Vlan = 50
	blue3Vlan = 60
)

type Switch struct {
	address               string
	port                  int
	sshPort               int
	username              string
	telnetUsername        string
	password              string
	mutex                 sync.Mutex
	configBackoffDuration time.Duration
	configPauseDuration   time.Duration
	Status                string
}

const ServerIpAddress = "10.0.100.5" // The DS will try to connect to this address only.

// DevMode allows driver station listeners to bind to all local IP addresses.
var DevMode = false

func NewSwitch(address, password string) *Switch {
	return &Switch{
		address:               address,
		port:                  switchTelnetPort,
		sshPort:               switchSSHPort,
		username:              "admin",
		password:              password,
		configBackoffDuration: switchConfigBackoffDurationSec * time.Second,
		configPauseDuration:   switchConfigPauseDurationSec * time.Second,
		Status:                "UNKNOWN",
	}
}

// Sets the login name used by SSH and by username/password Telnet authentication.
func (sw *Switch) SetUsername(username string) {
	sw.telnetUsername = username
	sw.username = username
	if sw.username == "" {
		sw.username = "admin"
	}
}

// Sets up wired networks for the given set of teams.
func (sw *Switch) ConfigureTeamEthernet(teams [6]*model.Team) error {
	// Make sure multiple configurations aren't being set at the same time.
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	sw.Status = "CONFIGURING"

	// Remove old team VLANs to reset the switch state.
	removeTeamVlansCommand := ""
	for vlan := 10; vlan <= 60; vlan += 10 {
		removeTeamVlansCommand += fmt.Sprintf(
			"interface Vlan%d\nno ip address\nno ip dhcp pool dhcp%d\n", vlan, vlan,
		)
	}
	_, err := sw.runConfigCommand(removeTeamVlansCommand)
	if err != nil {
		sw.Status = "ERROR"
		return err
	}
	time.Sleep(sw.configPauseDuration)

	// Create the new team VLANs.
	addTeamVlansCommand := ""
	addTeamVlan := func(team *model.Team, vlan int) {
		if team == nil {
			return
		}
		teamPartialIp := fmt.Sprintf("%d.%d", team.Id/100, team.Id%100)
		addTeamVlansCommand += fmt.Sprintf(
			"ip dhcp excluded-address 10.%s.1 10.%s.19\n"+
				"ip dhcp excluded-address 10.%s.200 10.%s.254\n"+
				"ip dhcp pool dhcp%d\n"+
				"network 10.%s.0 255.255.255.0\n"+
				"default-router 10.%s.%d\n"+
				"lease 7\n"+
				"interface Vlan%d\nip address 10.%s.%d 255.255.255.0\n",
			teamPartialIp,
			teamPartialIp,
			teamPartialIp,
			teamPartialIp,
			vlan,
			teamPartialIp,
			teamPartialIp,
			switchTeamGatewayAddress,
			vlan,
			teamPartialIp,
			switchTeamGatewayAddress,
		)
	}
	addTeamVlan(teams[0], red1Vlan)
	addTeamVlan(teams[1], red2Vlan)
	addTeamVlan(teams[2], red3Vlan)
	addTeamVlan(teams[3], blue1Vlan)
	addTeamVlan(teams[4], blue2Vlan)
	addTeamVlan(teams[5], blue3Vlan)
	if len(addTeamVlansCommand) > 0 {
		_, err = sw.runConfigCommand(addTeamVlansCommand)
		if err != nil {
			sw.Status = "ERROR"
			return err
		}
	}

	// Give some time for the configuration to take before another one can be attempted.
	time.Sleep(sw.configBackoffDuration)

	sw.Status = "ACTIVE"
	return nil
}

// Prefers SSH, falling back to Telnet only if the SSH TCP connection cannot be established.
func (sw *Switch) runCommand(command string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(sw.address, strconv.Itoa(sw.sshPort)), switchConnectTimeout)
	if err == nil {
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(switchCommandTimeout)); err != nil {
			return "", err
		}
		return sw.runSSHCommand(conn, command)
	}
	log.Printf("Switch SSH port unavailable; falling back to plaintext Telnet: %v", err)
	return sw.runTelnetCommand(command)
}

func (sw *Switch) runSSHCommand(conn net.Conn, command string) (string, error) {
	config := &ssh.ClientConfig{
		User: sw.username,
		Auth: []ssh.AuthMethod{ssh.Password(sw.password)},
		// Field switches use locally generated host keys, as do the SCC switches.
		HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
		HostKeyAlgorithms: append(ssh.SupportedAlgorithms().HostKeys, ssh.KeyAlgoRSA),
		Config: ssh.Config{
			KeyExchanges: []string{
				ssh.KeyExchangeCurve25519, ssh.KeyExchangeDH14SHA256, ssh.InsecureKeyExchangeDH1SHA1,
			},
			Ciphers: []string{ssh.CipherAES128GCM, ssh.CipherAES128CTR, ssh.InsecureCipherAES128CBC},
		},
	}
	sshConn, channels, requests, err := ssh.NewClientConn(conn, conn.RemoteAddr().String(), config)
	if err != nil {
		return "", fmt.Errorf("switch SSH handshake failed (Telnet fallback disabled): %w", err)
	}
	client := ssh.NewClient(sshConn, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("create switch SSH session: %w", err)
	}
	defer session.Close()
	input, err := session.StdinPipe()
	if err != nil {
		return "", err
	}
	output, err := session.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := session.RequestPty("vt100", 40, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return "", fmt.Errorf("request switch SSH terminal: %w", err)
	}
	if err := session.Shell(); err != nil {
		return "", fmt.Errorf("start switch SSH shell: %w", err)
	}
	return sw.runInteractiveCommand(bufio.NewReader(output), input, command)
}

func (sw *Switch) runTelnetCommand(command string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(sw.address, strconv.Itoa(sw.port)), switchConnectTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(switchCommandTimeout)); err != nil {
		return "", err
	}
	if sw.telnetUsername != "" {
		reader := &switchTelnetReader{reader: bufio.NewReader(conn), writer: conn}
		return sw.runInteractiveCommand(bufio.NewReader(reader), conn, command)
	}

	// Preserve the password-only login used by the original baseline configuration.
	writer := bufio.NewWriter(conn)
	_, err = writer.WriteString(
		fmt.Sprintf(
			"%s\nenable\n%s\nterminal length 0\n%sexit\n", sw.password, sw.password,
			command,
		),
	)
	if err != nil {
		return "", err
	}
	err = writer.Flush()
	if err != nil {
		return "", err
	}

	// Read the response.
	var reader bytes.Buffer
	_, err = reader.ReadFrom(conn)
	if err != nil {
		return "", err
	}
	output := reader.String()
	if err := switchCommandError(output); err != nil {
		return output, err
	}
	return output, nil
}

// Logs into the switch and runs the given command in global configuration mode. Reads the output
// and returns it as a string.
func (sw *Switch) runConfigCommand(command string) (string, error) {
	return sw.runCommand(fmt.Sprintf("config terminal\n%send\n", command))
}

func (sw *Switch) runInteractiveCommand(reader *bufio.Reader, writer io.Writer, command string) (string, error) {
	var output strings.Builder
	readPrompt := func() (string, error) {
		var response strings.Builder
		for {
			b, err := reader.ReadByte()
			if err != nil {
				return "", fmt.Errorf("read switch prompt: %w", err)
			}
			response.WriteByte(b)
			text := response.String()
			line := strings.TrimSpace(text[strings.LastIndex(text, "\n")+1:])
			lowerLine := strings.ToLower(line)
			if strings.HasSuffix(line, "#") || strings.HasSuffix(line, ">") ||
				strings.HasSuffix(lowerLine, "password:") || strings.HasSuffix(lowerLine, "username:") ||
				strings.HasSuffix(lowerLine, "login:") {
				output.WriteString(text)
				return line, switchCommandError(text)
			}
		}
	}
	send := func(text string) error {
		_, err := fmt.Fprintln(writer, text)
		return err
	}
	prompt, err := readPrompt()
	if err != nil {
		return output.String(), err
	}
	if strings.HasSuffix(strings.ToLower(prompt), "username:") ||
		strings.HasSuffix(strings.ToLower(prompt), "login:") {
		if err := send(sw.username); err != nil {
			return output.String(), err
		}
		prompt, err = readPrompt()
		if err != nil {
			return output.String(), err
		}
	}
	if strings.HasSuffix(strings.ToLower(prompt), "password:") {
		if err := send(sw.password); err != nil {
			return output.String(), err
		}
		prompt, err = readPrompt()
		if err != nil {
			return output.String(), err
		}
	}
	if strings.HasSuffix(prompt, ">") {
		if err := send("enable"); err != nil {
			return output.String(), err
		}
		prompt, err = readPrompt()
		if err != nil {
			return output.String(), err
		}
		if strings.HasSuffix(strings.ToLower(prompt), "password:") {
			if err := send(sw.password); err != nil {
				return output.String(), err
			}
			prompt, err = readPrompt()
			if err != nil {
				return output.String(), err
			}
		}
	}
	if !strings.HasSuffix(prompt, "#") {
		return output.String(), fmt.Errorf("switch did not grant privileged EXEC mode")
	}
	for _, line := range strings.Split("terminal length 0\n"+strings.TrimSpace(command), "\n") {
		if err := send(line); err != nil {
			return output.String(), err
		}
		prompt, err = readPrompt()
		if err != nil {
			return output.String(), err
		}
		if !strings.HasSuffix(prompt, "#") {
			return output.String(), fmt.Errorf("switch lost privileged mode")
		}
	}
	return output.String(), send("exit")
}

// Declines Telnet options; the switch CLI only needs a plain character stream.
type switchTelnetReader struct {
	reader *bufio.Reader
	writer io.Writer
}

func (r *switchTelnetReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		b, err := r.reader.ReadByte()
		if err != nil {
			return 0, err
		}
		if b != 255 {
			p[0] = b
			return 1, nil
		}
		command, err := r.reader.ReadByte()
		if err != nil {
			return 0, err
		}
		switch command {
		case 255:
			p[0] = 255
			return 1, nil
		case 251, 252, 253, 254:
			option, err := r.reader.ReadByte()
			if err != nil {
				return 0, err
			}
			if command == 251 || command == 253 {
				reply := byte(254)
				if command == 253 {
					reply = 252
				}
				if _, err := r.writer.Write([]byte{255, reply, option}); err != nil {
					return 0, err
				}
			}
		case 250:
			var previous byte
			for {
				next, err := r.reader.ReadByte()
				if err != nil {
					return 0, err
				}
				if previous == 255 && next == 240 {
					break
				}
				previous = next
			}
		}
	}
}

func switchCommandError(output string) error {
	for _, marker := range []string{
		"% Invalid", "% Error", "% Incomplete", "% Ambiguous", "% Authorization", "% Access denied", "% Bad",
	} {
		if strings.Contains(output, marker) {
			return fmt.Errorf("switch rejected command: %s", marker)
		}
	}
	return nil
}
