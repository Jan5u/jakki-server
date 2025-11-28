package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Jan5u/jakki-server/database"
	"github.com/quic-go/quic-go"
)

type ServerInfo struct {
	EventType string   `json:"type"`
	Channels  []string `json:"channels"`
}

type AdminRequest struct {
	Request string `json:"request"`
	Type    string `json:"type"`
	UserID  int    `json:"user_id,omitempty"`
}

type AdminResponse struct {
	EventType string      `json:"type"`
	Request   string      `json:"request"`
	Data      interface{} `json:"data"`
	Error     string      `json:"error,omitempty"`
}

type UserAction struct {
	EventType string `json:"type"`
	User      string `json:"user"`
	Channel   string `json:"channel"`
}

type voiceClient struct {
	user   string
	stream *quic.Stream
	send   chan []byte
}

type Server struct {
	addr     string
	listener *quic.Listener
	db       *database.DB

	// Channel management
	voiceChannels map[string]map[string]*voiceClient
	textChannels  map[string]bool
	eventStreams  []*quic.Stream

	// Authentication
	pendingChallenges  map[string][]byte
	authenticatedConns map[string]string
	connPublicKeys     map[string]string
	hasInitialAdmin    bool

	mu sync.RWMutex
}

func NewServer(addr string, db *database.DB) *Server {
	hasUsers, err := db.HasAnyUsers()
	if err != nil {
		log.Printf("Warning: Failed to check if users exist: %v", err)
		hasUsers = true
	}

	return &Server{
		addr:               addr,
		db:                 db,
		voiceChannels:      make(map[string]map[string]*voiceClient),
		textChannels:       make(map[string]bool),
		eventStreams:       make([]*quic.Stream, 0),
		pendingChallenges:  make(map[string][]byte),
		authenticatedConns: make(map[string]string),
		connPublicKeys:     make(map[string]string),
		hasInitialAdmin:    hasUsers,
	}
}

func (s *Server) RunServer() error {
	tlsConfig, err := createTLSConfig()
	if err != nil {
		return err
	}
	listener, err := quic.ListenAddr(s.addr, tlsConfig, nil)
	if err != nil {
		return err
	}
	s.listener = listener

	s.acceptStreamLoop(listener)
	return nil
}

func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) LoadChannels() error {
	allChannels, err := s.db.GetAllChannels()
	if err != nil {
		return err
	}

	for _, ch := range allChannels {
		if ch.Type == database.ChannelTypeVoice {
			s.mu.Lock()
			if _, exists := s.voiceChannels[ch.Name]; !exists {
				s.voiceChannels[ch.Name] = make(map[string]*voiceClient)
			}
			s.mu.Unlock()
			log.Printf("Loaded voice channel: %s", ch.Name)
		} else {
			s.mu.Lock()
			s.textChannels[ch.Name] = true
			s.mu.Unlock()
			log.Printf("Loaded text channel: %s", ch.Name)
		}
	}

	return nil
}

func GetDataDir() string {
	if dataDir := os.Getenv("JAKKI_DATA_DIR"); dataDir != "" {
		return dataDir
	}

	// Default paths to try
	paths := []string{
		"/jakkiserver_data",   // Docker container path
		"./jakkiserver_data",  // Local development path
		"../jakkiserver_data", // Alternative local path
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// If none exist, create local directory
	localPath := "./jakkiserver_data"
	if err := os.MkdirAll(localPath, 0750); err != nil {
		slog.Warn("Could not create data directory", "path", localPath, "error", err)
	}
	return localPath
}

func createTLSConfig() (*tls.Config, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  priv,
		}},
		NextProtos: []string{"jakki"},
		ServerName: "jakki",
		MinVersion: tls.VersionTLS13,
	}, nil
}

func (s *Server) acceptStreamLoop(listener *quic.Listener) {
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Error accepting stream: %v", err)
			return
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn *quic.Conn) {
	connID := fmt.Sprintf("%p", conn)

	defer func() {
		s.cleanupConnection(connID)
	}()

	authStream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Printf("Failed to open auth stream: %v", err)
		return
	}
	go s.handleAuthStream(conn, authStream)

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("AcceptStream error: %v", err)
			return
		}
		switch stream.StreamID() {
		case 0:
			go s.handleEventStream(conn, stream)
		case 4:
			go s.handleVoiceStream(conn, stream)
		default:
			log.Printf("Unknown stream id: %d", stream.StreamID())
			if err := stream.Close(); err != nil {
				log.Printf("Error closing unknown stream: %v", err)
			}
		}
	}
}

func (s *Server) handleAuthStream(conn *quic.Conn, stream *quic.Stream) {
	defer func() {
		if err := stream.Close(); err != nil {
			log.Printf("Error closing auth stream: %v", err)
		}
	}()

	connID := fmt.Sprintf("%p", conn)

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		log.Printf("Failed to generate challenge: %v", err)
		_, _ = stream.Write([]byte("error:internal server error"))
		return
	}

	s.mu.Lock()
	s.pendingChallenges[connID] = challenge
	s.mu.Unlock()

	challengeHex := hex.EncodeToString(challenge)
	if _, err := stream.Write([]byte(challengeHex)); err != nil {
		log.Printf("Failed to send challenge: %v", err)
		return
	}

	// wait for response
	buf := make([]byte, 8192)
	n, err := stream.Read(buf)
	if err != nil {
		log.Printf("Failed to read auth response: %v", err)
		s.mu.Lock()
		delete(s.pendingChallenges, connID)
		s.mu.Unlock()
		return
	}

	// username:publicKey_hex:signature_hex
	response := string(buf[:n])
	parts := strings.SplitN(response, ":", 3)
	if len(parts) != 3 {
		log.Printf("Invalid auth response format: got %d parts, expected 3. Response: %q (len=%d)", len(parts), response, len(response))
		_, _ = stream.Write([]byte("error:invalid format"))
		s.mu.Lock()
		delete(s.pendingChallenges, connID)
		s.mu.Unlock()
		return
	}

	username := parts[0]
	pubKeyHex := parts[1]
	signatureHex := parts[2]

	if err := validateUsername(username); err != nil {
		log.Printf("Invalid username: %v", err)
		_, _ = stream.Write([]byte(fmt.Sprintf("error:%v", err)))
		s.mu.Lock()
		delete(s.pendingChallenges, connID)
		s.mu.Unlock()
		return
	}

	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		log.Printf("Invalid public key: %v", err)
		_, _ = stream.Write([]byte("error:invalid public key"))
		s.mu.Lock()
		delete(s.pendingChallenges, connID)
		s.mu.Unlock()
		return
	}

	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		log.Printf("Invalid signature: %v", err)
		_, _ = stream.Write([]byte("error:invalid signature"))
		s.mu.Lock()
		delete(s.pendingChallenges, connID)
		s.mu.Unlock()
		return
	}

	s.mu.RLock()
	storedChallenge, exists := s.pendingChallenges[connID]
	s.mu.RUnlock()

	if !exists {
		log.Printf("Challenge not found for connection")
		_, _ = stream.Write([]byte("error:challenge expired"))
		return
	}

	if !ed25519.Verify(ed25519.PublicKey(pubKey), storedChallenge, signature) {
		log.Printf("Signature verification failed")
		_, _ = stream.Write([]byte("error:authentication failed"))
		s.mu.Lock()
		delete(s.pendingChallenges, connID)
		s.mu.Unlock()
		return
	}

	existingUser, userErr := s.db.GetUserByUsernameAndPublicKey(username, pubKeyHex)
	if userErr == nil {
		if !existingUser.IsApproved {
			log.Printf("User %s not yet approved by admin", username)
			_, _ = stream.Write([]byte("error:pending approval"))
			s.mu.Lock()
			delete(s.pendingChallenges, connID)
			s.mu.Unlock()
			return
		}
		if err := s.db.UpdateLastAuth(pubKeyHex); err != nil {
			log.Printf("Failed to update last auth: %v", err)
		}
	} else {
		isAvailable, err := s.db.IsUsernameAvailable(username)
		if err != nil {
			log.Printf("Failed to check username availability: %v", err)
			_, _ = stream.Write([]byte("error:internal server error"))
			s.mu.Lock()
			delete(s.pendingChallenges, connID)
			s.mu.Unlock()
			return
		}

		if !isAvailable {
			log.Printf("Username already taken: %s", username)
			_, _ = stream.Write([]byte("error:username already taken"))
			s.mu.Lock()
			delete(s.pendingChallenges, connID)
			s.mu.Unlock()
			return
		}

		// set first user as admin
		s.mu.Lock()
		isAdmin := !s.hasInitialAdmin
		if isAdmin {
			s.hasInitialAdmin = true
			log.Printf("Creating first user as admin: %s", username)
		}
		s.mu.Unlock()

		if err := s.db.CreateUser(username, pubKeyHex, isAdmin); err != nil {
			log.Printf("Failed to create user: %v", err)
			_, _ = stream.Write([]byte("error:failed to create user"))
			s.mu.Lock()
			delete(s.pendingChallenges, connID)
			s.mu.Unlock()
			return
		}

		if !isAdmin {
			log.Printf("New user %s created, pending admin approval", username)
			_, _ = stream.Write([]byte("error:pending approval"))
			s.mu.Lock()
			delete(s.pendingChallenges, connID)
			s.mu.Unlock()
			return
		}
	}

	s.mu.Lock()
	s.authenticatedConns[connID] = username
	s.connPublicKeys[connID] = pubKeyHex
	delete(s.pendingChallenges, connID)
	s.mu.Unlock()

	log.Printf("User authenticated: %s (pubkey: %s...)", username, pubKeyHex[:16])

	if _, err := stream.Write([]byte("ok")); err != nil {
		log.Printf("Failed to send ok response: %v", err)
	}
}

func validateUsername(username string) error {
	if len(username) < 3 || len(username) > 20 {
		return errors.New("username must be 3-20 characters")
	}
	matched, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", username)
	if !matched {
		return errors.New("username can only contain letters, numbers, underscore, and hyphen")
	}
	if strings.Contains(username, ":") {
		return errors.New("username cannot contain colon")
	}

	return nil
}

func (s *Server) handleEventStream(conn *quic.Conn, stream *quic.Stream) {
	defer func() {
		if err := stream.Close(); err != nil {
			log.Printf("Error closing event stream: %v", err)
		}
	}()

	// authenticate
	connID := fmt.Sprintf("%p", conn)
	s.mu.RLock()
	_, authenticated := s.authenticatedConns[connID]
	s.mu.RUnlock()

	if !authenticated {
		log.Printf("Unauthenticated connection attempted to access event stream")
		_, _ = stream.Write([]byte("error:not authenticated"))
		return
	}

	s.mu.Lock()
	s.eventStreams = append(s.eventStreams, stream)
	s.mu.Unlock()

	// Send server info with channels from database
	channelNames, err := s.db.GetAllChannelNames()
	if err != nil {
		log.Printf("Error getting channel names: %v", err)
		return
	}

	data := &ServerInfo{
		EventType: "ServerInfo",
		Channels:  channelNames,
	}
	encjson, err := json.Marshal(data)
	if err != nil {
		log.Println(err)
	}
	encjson = append(encjson, '\n')
	if _, err := stream.Write(encjson); err != nil {
		log.Printf("Error writing server info: %v", err)
		return
	}

	// handle incoming messages
	buf := make([]byte, 4096)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}

		message := string(buf[:n])
		log.Printf("Read %d bytes from EVENT stream: %s", n, message)

		// parse as admin request
		var adminReq AdminRequest
		if err := json.Unmarshal(buf[:n], &adminReq); err == nil && adminReq.Type == "admin_request" {
			s.handleAdminRequest(conn, stream, &adminReq)
		}
	}
}

func (s *Server) handleAdminRequest(conn *quic.Conn, stream *quic.Stream, adminReq *AdminRequest) {
	// check if user is admin
	connID := fmt.Sprintf("%p", conn)
	s.mu.RLock()
	username, authenticated := s.authenticatedConns[connID]
	pubKey, hasKey := s.connPublicKeys[connID]
	s.mu.RUnlock()

	if !authenticated || !hasKey {
		s.sendAdminError(stream, adminReq.Request, "not authenticated")
		return
	}
	user, err := s.db.GetUserByUsernameAndPublicKey(username, pubKey)
	if err != nil {
		s.sendAdminError(stream, adminReq.Request, "user not found")
		return
	}
	if !user.IsAdmin {
		s.sendAdminError(stream, adminReq.Request, "admin privileges required")
		return
	}

	// handle admin requests
	switch adminReq.Request {
	case "get_users":
		s.handleGetUsers(stream, adminReq.Request)
	case "approve_user":
		s.handleApproveUser(stream, adminReq)
	default:
		s.sendAdminError(stream, adminReq.Request, "unknown admin request")
	}
}

func (s *Server) handleGetUsers(stream *quic.Stream, request string) {
	users, err := s.db.GetAllUsers()
	if err != nil {
		s.sendAdminError(stream, request, "failed to retrieve users")
		return
	}

	response := AdminResponse{
		EventType: "admin_response",
		Request:   request,
		Data:      users,
	}

	s.sendAdminResponse(stream, &response)
}

func (s *Server) handleApproveUser(stream *quic.Stream, adminReq *AdminRequest) {
	if adminReq.UserID <= 0 {
		s.sendAdminError(stream, adminReq.Request, "invalid user_id")
		return
	}

	err := s.db.ApproveUserByID(adminReq.UserID)
	if err != nil {
		log.Printf("Failed to approve user ID %d: %v", adminReq.UserID, err)
		s.sendAdminError(stream, adminReq.Request, "failed to approve user")
		return
	}

	response := AdminResponse{
		EventType: "admin_response",
		Request:   adminReq.Request,
		Data:      map[string]interface{}{"user_id": adminReq.UserID, "status": "approved"},
	}

	s.sendAdminResponse(stream, &response)
}

func (s *Server) sendAdminError(stream *quic.Stream, request, errorMsg string) {
	response := AdminResponse{
		EventType: "admin_response",
		Request:   request,
		Error:     errorMsg,
	}
	s.sendAdminResponse(stream, &response)
}

func (s *Server) sendAdminResponse(stream *quic.Stream, response *AdminResponse) {
	jsonData, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshaling admin response: %v", err)
		return
	}

	jsonData = append(jsonData, '\n')
	if _, err := stream.Write(jsonData); err != nil {
		log.Printf("Error writing admin response: %v", err)
	}
}

func (s *Server) handleVoiceStream(conn *quic.Conn, stream *quic.Stream) {
	// authenticate
	connID := fmt.Sprintf("%p", conn)
	s.mu.RLock()
	username, authenticated := s.authenticatedConns[connID]
	s.mu.RUnlock()

	if !authenticated {
		log.Printf("Unauthenticated connection attempted to access voice stream")
		_, _ = stream.Write([]byte("error:not authenticated"))
		_ = stream.Close()
		return
	}

	buf := make([]byte, 8192)

	// when voice stream is created read from stream which channel to join
	n, err := stream.Read(buf)
	if err != nil {
		log.Printf("Read error: %v", err)
		return
	}
	log.Printf("Read %d bytes from voice stream", n)

	msg := string(buf[:n])
	log.Printf("Received from voice stream: %s", msg)

	channel := msg

	// check if channel exists
	s.mu.RLock()
	_, exists := s.voiceChannels[channel]
	s.mu.RUnlock()

	if !exists {
		log.Printf("Voice channel not found: %s", channel)
		_, _ = stream.Write([]byte("error:channel not found"))
		_ = stream.Close()
		return
	}

	s.addStreamToChannel(channel, username, stream)
	log.Printf("User %s joined %s", username, channel)

	// send ok for voice packets
	s.sendOkMessage(stream)

	// wait for voice packets
	for {
		n, err := stream.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}
		log.Printf("Read %d bytes from voice stream", n)

		// combine username with payload using a delimiter
		usernameBytes := []byte(username)
		delimiter := []byte(":")

		// create combined message: [username][delimiter][payload]
		combined := make([]byte, len(usernameBytes)+len(delimiter)+n)
		copy(combined, usernameBytes)
		copy(combined[len(usernameBytes):], delimiter)
		copy(combined[len(usernameBytes)+len(delimiter):], buf[:n])

		// broadcast to other users in the same channel
		s.broadcastVoiceToChannel(channel, username, combined)
	}
}

func (s *Server) sendOkMessage(stream *quic.Stream) {
	_, err := stream.Write([]byte("ok"))
	if err != nil {
		log.Printf("sendOkMessage: write error: %v", err)
	}
}

func (s *Server) broadcastVoiceToChannel(channel, sender string, data []byte) {
	// add data length to the packet
	packetLen := len(data)
	packet := make([]byte, 4+packetLen)
	packet[0] = byte(packetLen)
	packet[1] = byte(packetLen >> 8)
	packet[2] = byte(packetLen >> 16)
	packet[3] = byte(packetLen >> 24)
	copy(packet[4:], data)

	s.mu.RLock()
	channelStreams, exists := s.voiceChannels[channel]
	if !exists {
		s.mu.RUnlock()
		return
	}

	clients := make([]*voiceClient, 0, len(channelStreams))
	for user, c := range channelStreams {
		if user == sender {
			continue
		}
		clients = append(clients, c)
	}
	s.mu.RUnlock()

	for _, c := range clients {
		select {
		case c.send <- packet:
			// queued
		default:
			log.Printf("broadcastVoice: dropping packet for slow user %s", c.user)
		}
	}
}

func (s *Server) addStreamToChannel(channel, user string, stream *quic.Stream) *voiceClient {
	vc := &voiceClient{
		user:   user,
		stream: stream,
		send:   make(chan []byte, 32), // small buffer; tune as needed
	}

	s.mu.Lock()
	if _, ok := s.voiceChannels[channel]; !ok {
		s.voiceChannels[channel] = make(map[string]*voiceClient)
	}
	s.voiceChannels[channel][user] = vc
	s.mu.Unlock()

	log.Printf("Added stream for user %s to channel %s", user, channel)

	// start writer goroutine
	go s.voiceWriterLoop(channel, vc)

	// send event that user has joined this channel
	go s.broadcastEvent(UserAction{
		EventType: "UserJoin",
		User:      user,
		Channel:   channel,
	})
	return vc
}

func (s *Server) voiceWriterLoop(channel string, vc *voiceClient) {
	for msg := range vc.send {
		// set a write deadline so quic-go unblocks quickly for dead peers
		_ = vc.stream.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := vc.stream.Write(msg); err != nil {
			log.Printf("voiceWriterLoop: write error user=%s err=%v", vc.user, err)
			s.removeVoiceClient(channel, vc.user)
			return
		}
	}

	s.removeVoiceClient(channel, vc.user)
}

func (s *Server) removeVoiceClient(channel, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if channelStreams, ok := s.voiceChannels[channel]; ok {
		if vc, exists := channelStreams[user]; exists {
			delete(channelStreams, user)
			_ = vc.stream.Close()
			close(vc.send)
			log.Printf("Removed voice client user=%s from channel=%s", user, channel)
		}
	}
}

func (s *Server) cleanupConnection(connID string) {
	s.mu.Lock()
	username, wasAuthenticated := s.authenticatedConns[connID]
	delete(s.authenticatedConns, connID)
	delete(s.connPublicKeys, connID)
	delete(s.pendingChallenges, connID)
	s.mu.Unlock()

	if wasAuthenticated {
		log.Printf("Connection closed for user: %s", username)
		// Remove user from all voice channels
		s.removeUserFromAllChannels(username)
	}
}

func (s *Server) removeUserFromAllChannels(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for channelName, channelStreams := range s.voiceChannels {
		if vc, exists := channelStreams[username]; exists {
			delete(channelStreams, username)
			_ = vc.stream.Close()
			close(vc.send)
			log.Printf("Removed user %s from channel %s on disconnect", username, channelName)

			go s.broadcastEvent(UserAction{
				EventType: "UserLeave",
				User:      username,
				Channel:   channelName,
			})
		}
	}
}

func (s *Server) broadcastEvent(event UserAction) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("broadcastEvent: marshal error: %v", err)
		return
	}
	data = append(data, '\n')
	s.mu.RLock()
	streams := make([]*quic.Stream, len(s.eventStreams))
	copy(streams, s.eventStreams)
	s.mu.RUnlock()
	for _, stream := range streams {
		_ = (*stream).SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := (*stream).Write(data); err != nil {
			log.Printf("broadcastEvent: write error: %v", err)
		}
	}
}
