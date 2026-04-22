package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	ctls "github.com/platinvm/pokemmo-ctls"
)

const (
	serverAddr = "loginserver.pokemmo.com:2106"

	// Client -> Server opcodes.
	opLoginRequest    = 0x11
	opToSConfirmation = 0x04
	opMfaResponse     = 0x08

	// Server -> Client opcodes.
	opLoginResponse   = 0x01
	opGameServerList  = 0x22
	opLoginKick       = 0x05
	opSentCredentials = 0x07
	opMfaChallenge    = 0x08
	opToS             = 0x14
	opExistingSession = 0x26

	clientRevision       = 31914
	installationRevision = 31914
)

// loginState maps server response state bytes to descriptions.
var loginStateNames = map[byte]string{
	0:  "AUTHED",
	1:  "SYSTEM_ERROR",
	2:  "INVALID_PASSWORD",
	3:  "AUTHED_HALF",
	6:  "NO_GS_AVAILABLE",
	7:  "ALREADY_LOGGED_IN",
	8:  "SERVER_DOWN",
	9:  "ACCOUNT_ISSUE",
	16: "GM_ONLY",
	22: "BAN_IP",
	23: "RATE_LIMITED",
	24: "ERROR_CONNECTING_AUTH_SERVER",
	25: "INVALID_TOS_REVISION",
	26: "BLOCKLIST_IP",
	27: "ANDROID_ALPHA_PERMISSION",
	28: "BLOCKLIST_IP_RANGE",
	29: "ERROR_CONNECTING_GAME_SERVER",
	30: "INVALID_SAVED_CREDENTIALS",
	31: "ERROR_CONNECTING_FIREWALL",
	32: "RATE_LIMITED_2FA",
	33: "WRONG_CODE_2FA",
	34: "CLIENT_OUT_OF_DATE",
	35: "EXTRA_VALIDATION_FAILED",
	36: "REQUIRE_QQ_FOR_ACCOUNT",
}

type appState int

const (
	stateLogin appState = iota
	stateConnecting
	stateAwaitMFA
	stateDone
	stateError
)

type logTab int

const (
	tabEvents logTab = iota
	tabPackets
)

type gameServer struct {
	ID             byte
	Name           string
	CurrentPlayers uint16
	MaxPlayers     uint16
	Joinable       bool
}

type loginResponseInfo struct {
	State         byte
	Name          string
	RateLimitEnds string
	AuthToken     string
}

type packetRecord struct {
	Time      string
	Direction string
	Opcode    byte
	Payload   int
	Dump      string
}

type connectedMsg struct {
	conn *ctls.Conn
}

type loginResponseMsg struct {
	info loginResponseInfo
}

type mfaChallengeMsg struct {
	email string
}

type sentCredentialsMsg struct {
	username string
	key      string
}

type tosMsg struct {
	confirmationKey byte
}

type existingSessionMsg struct {
	sessionID uint64
}

type gameServerListMsg struct {
	servers []gameServer
}

type packetMsg struct {
	packet packetRecord
}

type statusMsg string

type errMsg struct {
	err error
}

type model struct {
	state appState

	usernameInput textinput.Model
	passwordInput textinput.Model
	mfaInput      textinput.Model
	focusIndex    int

	spinner spinner.Model

	conn *ctls.Conn

	statusLine string
	logs       []string
	packets    []packetRecord
	servers    []gameServer

	activeTab    logTab
	eventScroll  int
	packetScroll int
	packetIndex  int

	mfaEmail string
	err      error

	width  int
	height int

	eventCh   chan tea.Msg
	mfaCodeCh chan string
}

var (
	appNameStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("229")).
			Background(lipgloss.Color("57")).
			Padding(0, 1)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(1, 2)

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("111")).
			Bold(true)

	mutedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("204")).
			Bold(true)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("42")).
			Bold(true)

	buttonStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("31")).
			Padding(0, 2)

	buttonActiveStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("232")).
				Background(lipgloss.Color("78")).
				Bold(true).
				Padding(0, 2)

	tabStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("250")).
			Background(lipgloss.Color("238")).
			Padding(0, 1)

	activeTabStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("232")).
			Background(lipgloss.Color("117")).
			Bold(true).
			Padding(0, 1)
)

func main() {
	m := initialModel()
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI failed: %v\n", err)
		os.Exit(1)
	}
}

func initialModel() model {
	usernameInput := textinput.New()
	usernameInput.Placeholder = "Username"
	usernameInput.CharLimit = 64
	usernameInput.Width = 32
	usernameInput.Focus()

	passwordInput := textinput.New()
	passwordInput.Placeholder = "Password"
	passwordInput.CharLimit = 128
	passwordInput.Width = 32
	passwordInput.EchoMode = textinput.EchoPassword
	passwordInput.EchoCharacter = '•'

	mfaInput := textinput.New()
	mfaInput.Placeholder = "6-digit code"
	mfaInput.CharLimit = 12
	mfaInput.Width = 24

	spin := spinner.New()
	spin.Spinner = spinner.Dot
	spin.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))

	return model{
		state:         stateLogin,
		usernameInput: usernameInput,
		passwordInput: passwordInput,
		mfaInput:      mfaInput,
		focusIndex:    0,
		spinner:       spin,
		statusLine:    "Fill credentials and press Enter.",
		activeTab:     tabEvents,
		packetIndex:   -1,
		eventCh:       make(chan tea.Msg, 64),
		mfaCodeCh:     make(chan string),
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(waitForNetworkEvent(m.eventCh), m.spinner.Tick)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.conn != nil {
				_ = m.conn.Close()
			}
			return m, tea.Quit
		}

		if updated, consumed := m.handleTabInput(msg); consumed {
			return updated, nil
		}

		switch m.state {
		case stateLogin:
			var cmd tea.Cmd
			m, cmd = m.updateLoginInputs(msg)
			cmds = append(cmds, cmd)

		case stateAwaitMFA:
			var cmd tea.Cmd
			m, cmd = m.updateMFAInput(msg)
			cmds = append(cmds, cmd)
		}

	case connectedMsg:
		m.conn = msg.conn
		m.state = stateConnecting
		m.pushLog("CTLS handshake complete.")
		m.statusLine = "Connected. Waiting for login responses..."
		cmds = append(cmds, waitForNetworkEvent(m.eventCh))

	case loginResponseMsg:
		m.pushLog(fmt.Sprintf("LoginResponse: %d (%s)", msg.info.State, msg.info.Name))
		if msg.info.RateLimitEnds != "" {
			m.pushLog("Rate limit ends: " + msg.info.RateLimitEnds)
		}
		if msg.info.AuthToken != "" {
			m.pushLog("Auth token received.")
		}
		switch msg.info.State {
		case 0:
			m.statusLine = "Login successful. Receiving account/session data..."
			m.state = stateConnecting
		case 3:
			m.statusLine = "MFA required. Waiting for challenge..."
			m.state = stateConnecting
		default:
			m.state = stateError
			m.err = fmt.Errorf("login failed: %s", msg.info.Name)
			if m.conn != nil {
				_ = m.conn.Close()
			}
		}
		cmds = append(cmds, waitForNetworkEvent(m.eventCh))

	case mfaChallengeMsg:
		m.mfaEmail = msg.email
		m.mfaInput.SetValue("")
		m.mfaInput.Focus()
		m.state = stateAwaitMFA
		m.statusLine = "MFA challenge received. Enter your code."
		m.pushLog("MFA challenge sent to: " + msg.email)
		cmds = append(cmds, waitForNetworkEvent(m.eventCh))

	case sentCredentialsMsg:
		m.pushLog(fmt.Sprintf("SentCredentials: username=%q key=%q", msg.username, msg.key))
		cmds = append(cmds, waitForNetworkEvent(m.eventCh))

	case tosMsg:
		m.pushLog(fmt.Sprintf("ToS auto-accepted (confirmationKey=%d)", msg.confirmationKey))
		cmds = append(cmds, waitForNetworkEvent(m.eventCh))

	case existingSessionMsg:
		m.pushLog(fmt.Sprintf("ExistingSession: sessionID=%d", msg.sessionID))
		cmds = append(cmds, waitForNetworkEvent(m.eventCh))

	case gameServerListMsg:
		m.servers = msg.servers
		m.state = stateDone
		m.statusLine = fmt.Sprintf("Received %d game server(s).", len(msg.servers))
		if m.conn != nil {
			_ = m.conn.Close()
			m.conn = nil
		}
		cmds = append(cmds, waitForNetworkEvent(m.eventCh))

	case statusMsg:
		m.pushLog(string(msg))
		m.statusLine = string(msg)
		cmds = append(cmds, waitForNetworkEvent(m.eventCh))

	case packetMsg:
		m.packets = append(m.packets, msg.packet)
		if len(m.packets) > 300 {
			m.packets = m.packets[len(m.packets)-300:]
		}
		m.packetIndex = len(m.packets) - 1
		m.packetScroll = 0
		cmds = append(cmds, waitForNetworkEvent(m.eventCh))

	case errMsg:
		m.state = stateError
		m.err = msg.err
		m.statusLine = "Error: " + msg.err.Error()
		if m.conn != nil {
			_ = m.conn.Close()
			m.conn = nil
		}
		cmds = append(cmds, waitForNetworkEvent(m.eventCh))
	}

	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	header := appNameStyle.Render("PokeMMO Terminal Selfbot")
	body := m.renderBody()
	tabs := m.renderTabPanel()

	content := lipgloss.JoinVertical(lipgloss.Left, header, body, tabs)

	if m.width > 0 && m.height > 0 {
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Top, content)
	}

	return content
}

func (m model) updateLoginInputs(msg tea.KeyMsg) (model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg.String() {
	case "tab", "shift+tab", "up", "down":
		if msg.String() == "up" || msg.String() == "shift+tab" {
			m.focusIndex--
		} else {
			m.focusIndex++
		}
		if m.focusIndex > 2 {
			m.focusIndex = 0
		} else if m.focusIndex < 0 {
			m.focusIndex = 2
		}

		m.usernameInput.Blur()
		m.passwordInput.Blur()

		switch m.focusIndex {
		case 0:
			m.usernameInput.Focus()
		case 1:
			m.passwordInput.Focus()
		}

		return m, nil

	case "enter":
		if m.focusIndex < 2 {
			m.focusIndex = 2
			m.usernameInput.Blur()
			m.passwordInput.Blur()
			return m, nil
		}

		username := strings.TrimSpace(m.usernameInput.Value())
		password := strings.TrimSpace(m.passwordInput.Value())
		if username == "" || password == "" {
			m.statusLine = "Username and password are required."
			return m, nil
		}

		m.state = stateConnecting
		m.statusLine = "Connecting to login server..."
		m.pushLog("Dialing " + serverAddr)
		return m, startSessionCmd(username, password, m.eventCh, m.mfaCodeCh)
	}

	if m.focusIndex == 1 {
		m.passwordInput, cmd = m.passwordInput.Update(msg)
	} else {
		m.usernameInput, cmd = m.usernameInput.Update(msg)
	}

	return m, cmd
}

func (m model) updateMFAInput(msg tea.KeyMsg) (model, tea.Cmd) {
	if msg.String() == "enter" {
		code := strings.TrimSpace(m.mfaInput.Value())
		if code == "" {
			m.statusLine = "Enter a valid MFA code."
			return m, nil
		}
		m.state = stateConnecting
		m.statusLine = "Submitting MFA code..."
		m.pushLog("Sending MFA response.")
		go func(ch chan string, code string) {
			ch <- code
		}(m.mfaCodeCh, code)
		m.mfaInput.SetValue("")
		return m, nil
	}

	var cmd tea.Cmd
	m.mfaInput, cmd = m.mfaInput.Update(msg)
	return m, cmd
}

func (m *model) pushLog(s string) {
	timestamp := time.Now().Format("15:04:05")
	m.logs = append(m.logs, fmt.Sprintf("[%s] %s", timestamp, s))
	if len(m.logs) > 200 {
		m.logs = m.logs[len(m.logs)-200:]
	}
	if len(m.logs) > 0 {
		m.eventScroll = max(0, len(m.logs)-m.tabContentHeight())
	}
}

func (m model) renderBody() string {
	panelWidth := max(32, m.width-4)

	switch m.state {
	case stateLogin:
		usernameField := m.usernameInput.View()
		passwordField := m.passwordInput.View()
		submit := buttonStyle.Render("Connect")
		if m.focusIndex == 2 {
			submit = buttonActiveStyle.Render("Connect")
		}

		content := labelStyle.Render("Login") + "\n\n" +
			labelStyle.Render("Username") + "\n" + usernameField + "\n\n" +
			labelStyle.Render("Password") + "\n" + passwordField + "\n\n" +
			labelStyle.Render("Status") + "\n" + m.renderStatusLine() + "\n\n" +
			submit + "\n\n" +
			mutedStyle.Render("Tab to switch fields, Enter to submit, q to quit")

		return panelStyle.Width(panelWidth).Render(content)

	case stateAwaitMFA:
		content := labelStyle.Render("Two-Factor Authentication") + "\n\n" +
			mutedStyle.Render("Challenge sent to: "+m.mfaEmail) + "\n\n" +
			labelStyle.Render("MFA Code") + "\n" + m.mfaInput.View() + "\n\n" +
			labelStyle.Render("Status") + "\n" + m.renderStatusLine() + "\n\n" +
			mutedStyle.Render("Press Enter to send code")
		return panelStyle.Width(panelWidth).Render(content)

	case stateConnecting:
		content := labelStyle.Render("Session") + "\n\n" +
			m.spinner.View() + " " + m.renderStatusLine() + "\n\n" +
			mutedStyle.Render("Waiting for server events...")
		return panelStyle.Width(panelWidth).Render(content)

	case stateDone:
		servers := m.renderServers()
		content := successStyle.Render("Login Flow Complete") + "\n\n" +
			labelStyle.Render("Status") + "\n" + m.renderStatusLine() + "\n\n" +
			servers + "\n\n" +
			mutedStyle.Render("Press q to quit")
		return panelStyle.Width(panelWidth).Render(content)

	case stateError:
		errText := "Unknown error"
		if m.err != nil {
			errText = m.err.Error()
		}
		content := errorStyle.Render("Session Error") + "\n\n" +
			labelStyle.Render("Status") + "\n" + m.renderStatusLine() + "\n\n" +
			errText + "\n\n" +
			mutedStyle.Render("Press q to quit")
		return panelStyle.Width(panelWidth).Render(content)

	default:
		return panelStyle.Width(panelWidth).Render("Initializing...")
	}
}

func (m model) renderStatusLine() string {
	if m.state == stateError {
		return errorStyle.Render(m.statusLine)
	}
	if m.state == stateDone {
		return successStyle.Render(m.statusLine)
	}
	return m.statusLine
}

func (m model) renderTabPanel() string {
	panelWidth := max(32, m.width-4)
	tabs := m.renderTabs()

	var content string
	if m.activeTab == tabPackets {
		content = m.renderPacketView()
	} else {
		content = m.renderEventsView()
	}

	footer := mutedStyle.Render("F1 Events | F2 Packets | PgUp/PgDn scroll | n/p packet")
	return panelStyle.Width(panelWidth).Render(tabs + "\n" + content + "\n\n" + footer)
}

func (m model) renderTabs() string {
	events := tabStyle.Render(" Events ")
	packets := tabStyle.Render(" Packet Visualizer ")
	if m.activeTab == tabEvents {
		events = activeTabStyle.Render(" Events ")
	} else {
		packets = activeTabStyle.Render(" Packet Visualizer ")
	}
	return lipgloss.JoinHorizontal(lipgloss.Left, events, " ", packets)
}

func (m model) renderEventsView() string {
	if len(m.logs) == 0 {
		return mutedStyle.Render("No events yet.")
	}

	maxLines := m.tabContentHeight()
	maxStart := max(0, len(m.logs)-maxLines)
	start := clampInt(m.eventScroll, 0, maxStart)
	end := min(len(m.logs), start+maxLines)
	return strings.Join(m.logs[start:end], "\n")
}

func (m model) renderPacketView() string {
	if len(m.packets) == 0 {
		return mutedStyle.Render("No packets captured yet.")
	}

	idx := clampInt(m.packetIndex, 0, len(m.packets)-1)
	pkt := m.packets[idx]

	header := []string{
		fmt.Sprintf("Packet %d/%d", idx+1, len(m.packets)),
		fmt.Sprintf("Time: %s", pkt.Time),
		fmt.Sprintf("Direction: %s", pkt.Direction),
		fmt.Sprintf("Opcode: 0x%02X", pkt.Opcode),
		fmt.Sprintf("Payload Bytes: %d", pkt.Payload),
		"",
		"Hex Dump:",
	}

	dump := strings.TrimRight(pkt.Dump, "\n")
	if dump == "" {
		dump = "(empty packet)"
	}
	lines := append(header, strings.Split(dump, "\n")...)

	maxLines := m.tabContentHeight()
	maxStart := max(0, len(lines)-maxLines)
	start := clampInt(m.packetScroll, 0, maxStart)
	end := min(len(lines), start+maxLines)
	return strings.Join(lines[start:end], "\n")
}

func (m model) tabContentHeight() int {
	if m.height <= 0 {
		return 10
	}
	return max(6, m.height/3)
}

func (m model) handleTabInput(msg tea.KeyMsg) (model, bool) {
	inEditableState := m.state == stateLogin || m.state == stateAwaitMFA

	switch msg.String() {
	case "f1":
		m.activeTab = tabEvents
		return m, true
	case "f2":
		m.activeTab = tabPackets
		if len(m.packets) > 0 && m.packetIndex < 0 {
			m.packetIndex = len(m.packets) - 1
		}
		return m, true
	case "pgup", "ctrl+u":
		m = m.scrollActiveTab(-max(1, m.tabContentHeight()/2))
		return m, true
	case "pgdown", "ctrl+d":
		m = m.scrollActiveTab(max(1, m.tabContentHeight()/2))
		return m, true
	}

	if inEditableState {
		return m, false
	}

	switch msg.String() {
	case "up", "k":
		m = m.scrollActiveTab(-1)
		return m, true
	case "down", "j":
		m = m.scrollActiveTab(1)
		return m, true
	case "n":
		if m.activeTab == tabPackets && len(m.packets) > 0 {
			m.packetIndex = min(len(m.packets)-1, m.packetIndex+1)
			m.packetScroll = 0
			return m, true
		}
	case "p":
		if m.activeTab == tabPackets && len(m.packets) > 0 {
			m.packetIndex = max(0, m.packetIndex-1)
			m.packetScroll = 0
			return m, true
		}
	}

	return m, false
}

func (m model) scrollActiveTab(delta int) model {
	if delta == 0 {
		return m
	}

	if m.activeTab == tabPackets {
		if len(m.packets) == 0 {
			m.packetScroll = 0
			return m
		}
		idx := clampInt(m.packetIndex, 0, len(m.packets)-1)
		pkt := m.packets[idx]
		headerLines := 7
		dumpLines := len(strings.Split(strings.TrimRight(pkt.Dump, "\n"), "\n"))
		totalLines := headerLines + dumpLines
		maxStart := max(0, totalLines-m.tabContentHeight())
		m.packetScroll = clampInt(m.packetScroll+delta, 0, maxStart)
		return m
	}

	maxStart := max(0, len(m.logs)-m.tabContentHeight())
	m.eventScroll = clampInt(m.eventScroll+delta, 0, maxStart)
	return m
}

func (m model) renderServers() string {
	if len(m.servers) == 0 {
		return mutedStyle.Render("No game servers returned by the login server.")
	}

	var b strings.Builder
	for _, s := range m.servers {
		joinState := "No"
		if s.Joinable {
			joinState = "Yes"
		}
		fmt.Fprintf(&b, "[%d] %-20s %4d/%-4d joinable=%s\n", s.ID, s.Name, s.CurrentPlayers, s.MaxPlayers, joinState)
	}
	return strings.TrimRight(b.String(), "\n")
}

func waitForNetworkEvent(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		return <-ch
	}
}

func startSessionCmd(username, password string, eventCh chan tea.Msg, mfaCodeCh <-chan string) tea.Cmd {
	return func() tea.Msg {
		go runSession(username, password, eventCh, mfaCodeCh)
		return nil
	}
}

func runSession(username, password string, eventCh chan tea.Msg, mfaCodeCh <-chan string) {
	config := ctls.Config{InsecureSkipVerify: true}

	conn, err := ctls.Dial("tcp4", serverAddr, &config)
	if err != nil {
		eventCh <- errMsg{err: fmt.Errorf("CTLS dial failed: %w", err)}
		return
	}
	eventCh <- connectedMsg{conn: conn}

	hwid := computeHardwareFingerprint()
	loginReq := buildLoginRequest(username, password, hwid)
	if err := writePacket(conn, opLoginRequest, loginReq); err != nil {
		eventCh <- errMsg{err: fmt.Errorf("failed to send login request: %w", err)}
		_ = conn.Close()
		return
	}
	eventCh <- packetMsg{packet: makePacketRecord("TX", opLoginRequest, loginReq)}
	eventCh <- statusMsg("Login request sent.")

	for {
		opcode, payload, err := readPacket(conn)
		if err != nil {
			eventCh <- errMsg{err: fmt.Errorf("read error: %w", err)}
			_ = conn.Close()
			return
		}
		eventCh <- packetMsg{packet: makePacketRecord("RX", opcode, payload)}

		switch opcode {
		case opLoginResponse:
			info := parseLoginResponse(payload)
			eventCh <- loginResponseMsg{info: info}
			if info.State != 0 && info.State != 3 {
				_ = conn.Close()
				return
			}

		case opMfaChallenge:
			email := parseMfaChallenge(payload)
			eventCh <- mfaChallengeMsg{email: email}

			code, ok := <-mfaCodeCh
			if !ok {
				eventCh <- errMsg{err: fmt.Errorf("MFA input channel closed")}
				_ = conn.Close()
				return
			}

			var buf []byte
			buf = appendUTF16LE(buf, code)
			if err := writePacket(conn, opMfaResponse, buf); err != nil {
				eventCh <- errMsg{err: fmt.Errorf("failed to send MFA response: %w", err)}
				_ = conn.Close()
				return
			}
			eventCh <- packetMsg{packet: makePacketRecord("TX", opMfaResponse, buf)}
			eventCh <- statusMsg("MFA response sent.")

		case opSentCredentials:
			username, key := parseSentCredentials(payload)
			eventCh <- sentCredentialsMsg{username: username, key: key}

		case opToS:
			confirmationKey, err := parseToS(payload)
			if err != nil {
				eventCh <- errMsg{err: err}
				_ = conn.Close()
				return
			}
			if err := writePacket(conn, opToSConfirmation, []byte{confirmationKey}); err != nil {
				eventCh <- errMsg{err: fmt.Errorf("failed to send ToS confirmation: %w", err)}
				_ = conn.Close()
				return
			}
			eventCh <- packetMsg{packet: makePacketRecord("TX", opToSConfirmation, []byte{confirmationKey})}
			eventCh <- tosMsg{confirmationKey: confirmationKey}

		case opLoginKick:
			eventCh <- errMsg{err: fmt.Errorf("kicked by server")}
			_ = conn.Close()
			return

		case opExistingSession:
			sessionID, err := parseExistingSession(payload)
			if err != nil {
				eventCh <- errMsg{err: err}
				_ = conn.Close()
				return
			}
			eventCh <- existingSessionMsg{sessionID: sessionID}

		case opGameServerList:
			servers, err := parseGameServerList(payload)
			if err != nil {
				eventCh <- errMsg{err: err}
				_ = conn.Close()
				return
			}
			eventCh <- gameServerListMsg{servers: servers}
			_ = conn.Close()
			return

		default:
			eventCh <- statusMsg(fmt.Sprintf("Unknown opcode 0x%02X (%d bytes payload)", opcode, len(payload)))
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clampInt(v, lo, hi int) int {
	if hi < lo {
		return lo
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func makePacketRecord(direction string, opcode byte, payload []byte) packetRecord {
	raw := make([]byte, 1+len(payload))
	raw[0] = opcode
	copy(raw[1:], payload)
	return packetRecord{
		Time:      time.Now().Format("15:04:05.000"),
		Direction: direction,
		Opcode:    opcode,
		Payload:   len(payload),
		Dump:      hex.Dump(raw),
	}
}

func writePacket(conn *ctls.Conn, opcode byte, payload []byte) error {
	buf := make([]byte, 1+len(payload))
	buf[0] = opcode
	copy(buf[1:], payload)
	_, err := conn.Write(buf)
	return err
}

func readPacket(conn *ctls.Conn) (opcode byte, payload []byte, err error) {
	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	if n < 1 {
		return 0, nil, fmt.Errorf("empty packet")
	}
	return buf[0], buf[1:n], nil
}

// --- Packet Builders ---

func buildLoginRequest(username, password string, hwid []byte) []byte {
	// Server expects SHA-1 hex digest of the password, not plaintext.
	passwordHash := sha1Hex(password)

	var buf []byte
	buf = appendUTF16LE(buf, username)
	buf = append(buf, 0) // useSessionToken = false
	buf = append(buf, byte(len(hwid)))
	buf = append(buf, hwid...)
	buf = append(buf, 0) // method type: Password
	buf = appendUTF16LE(buf, passwordHash)
	buf = append(buf, 0) // stayLoggedIn = false
	buf = appendUTF16LE(buf, "en")
	buf = appendLE32(buf, clientRevision)
	buf = appendLE32(buf, installationRevision)
	buf = append(buf, 1) // os: 0=Windows, 1=Linux, 2=Mac
	buf = append(buf, 0) // runtimeExtraBytes length = 0
	return buf
}

// sha1Hex returns the lowercase hex-encoded SHA-1 digest of s.
func sha1Hex(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// computeHardwareFingerprint returns a SHA-256 digest of the machine identity.
func computeHardwareFingerprint() []byte {
	var identity string
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(path)
		if err == nil {
			id := strings.TrimSpace(string(data))
			if len(id) >= 10 {
				identity = id
				break
			}
		}
	}
	if identity == "" {
		// Fallback: use hostname + OS info.
		hostname, _ := os.Hostname()
		identity = fmt.Sprintf("linux|amd64|en|%s||", hostname)
	}
	digest := sha256.Sum256([]byte(identity))
	return digest[:]
}

func parseLoginResponse(payload []byte) loginResponseInfo {
	info := loginResponseInfo{State: 1, Name: "SYSTEM_ERROR"}
	if len(payload) < 1 {
		return info
	}
	state := payload[0]
	name := loginStateNames[state]
	if name == "" {
		name = "UNKNOWN"
	}
	info.State = state
	info.Name = name

	rest := payload[1:]
	if state == 23 || state == 32 { // RATE_LIMITED or RATE_LIMITED_2FA
		if len(rest) >= 8 {
			epochSec := int64(binary.LittleEndian.Uint64(rest[:8]))
			t := time.Unix(epochSec, 0).UTC()
			info.RateLimitEnds = t.Format(time.RFC3339)
		}
	}
	if state == 0 { // AUTHED
		if len(rest) > 0 {
			s := readUTF16LE(rest)
			if s != "" {
				info.AuthToken = s
			}
		}
	}
	return info
}

func parseMfaChallenge(payload []byte) string {
	if len(payload) < 1 {
		return ""
	}
	_ = payload[0] // unk byte
	return readUTF16LE(payload[1:])
}

func parseSentCredentials(payload []byte) (string, string) {
	username, rest := readUTF16LEWithRest(payload)
	key, _ := readUTF16LEWithRest(rest)
	return username, key
}

func parseToS(payload []byte) (byte, error) {
	if len(payload) < 1 {
		return 0, fmt.Errorf("ToS payload too short")
	}
	return payload[0], nil
}

func parseExistingSession(payload []byte) (uint64, error) {
	if len(payload) < 8 {
		return 0, fmt.Errorf("ExistingSession payload too short")
	}
	return binary.LittleEndian.Uint64(payload[:8]), nil
}

func parseGameServerList(payload []byte) ([]gameServer, error) {
	if len(payload) < 1 {
		return nil, fmt.Errorf("GameServerList empty")
	}
	count := int(payload[0])
	if count == 0 {
		return nil, nil
	}

	servers := make([]gameServer, 0, count)
	off := 2
	for i := 0; i < count && off < len(payload); i++ {
		if off >= len(payload) {
			break
		}
		id := payload[off]
		off++
		name, rest := readUTF16LEWithRest(payload[off:])
		off = len(payload) - len(rest)
		var currentPlayers, maxPlayers uint16
		var joinable bool
		if len(rest) >= 5 {
			currentPlayers = binary.LittleEndian.Uint16(rest[:2])
			maxPlayers = binary.LittleEndian.Uint16(rest[2:4])
			joinable = rest[4] != 0
			off += 5
		}

		servers = append(servers, gameServer{
			ID:             id,
			Name:           name,
			CurrentPlayers: currentPlayers,
			MaxPlayers:     maxPlayers,
			Joinable:       joinable,
		})
	}

	return servers, nil
}

// --- UTF-16 LE Helpers ---

// appendUTF16LE appends a null-terminated UTF-16 LE encoded string to buf.
func appendUTF16LE(buf []byte, s string) []byte {
	encoded := utf16.Encode([]rune(s))
	for _, u := range encoded {
		buf = append(buf, byte(u), byte(u>>8))
	}
	// Null terminator.
	buf = append(buf, 0, 0)
	return buf
}

// readUTF16LE reads a null-terminated UTF-16 LE string from data.
func readUTF16LE(data []byte) string {
	s, _ := readUTF16LEWithRest(data)
	return s
}

// readUTF16LEWithRest reads a null-terminated UTF-16 LE string and returns
// the remaining bytes after the null terminator.
func readUTF16LEWithRest(data []byte) (string, []byte) {
	var codes []uint16
	for i := 0; i+1 < len(data); i += 2 {
		c := binary.LittleEndian.Uint16(data[i : i+2])
		if c == 0 {
			return string(utf16.Decode(codes)), data[i+2:]
		}
		codes = append(codes, c)
	}
	return string(utf16.Decode(codes)), nil
}

// appendLE32 appends a uint32 in little-endian to buf.
func appendLE32(buf []byte, v int) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	return append(buf, b[:]...)
}
