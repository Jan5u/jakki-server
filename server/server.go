package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"math"
	"math/big"
	"os"
	"path/filepath"
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
	EventType string `json:"type"`
	Request   string `json:"request"`
	Data      any    `json:"data"`
	Error     string `json:"error,omitempty"`
}

type UserAction struct {
	EventType string `json:"type"`
	User      string `json:"user"`
	Channel   string `json:"channel"`
}

type IncomingMessage struct {
	EventType  string `json:"type"`
	Channel    string `json:"channel"`
	Content    string `json:"content"`
	Compressed bool   `json:"compressed"`
}

type OutgoingMessage struct {
	EventType  string `json:"type"`
	Channel    string `json:"channel"`
	Content    string `json:"content"`
	Compressed bool   `json:"compressed"`
	User       string `json:"user"`
	Timestamp  string `json:"timestamp"`
	ID         int    `json:"id"`
}

type MessageHistoryRequest struct {
	EventType string `json:"type"`
	Request   string `json:"request"`
	Channel   string `json:"channel"`
	Limit     int    `json:"limit,omitempty"`
	Before    int    `json:"before,omitempty"`
}

type MessageHistoryResponse struct {
	EventType string            `json:"type"`
	Request   string            `json:"request"`
	Channel   string            `json:"channel"`
	Messages  []OutgoingMessage `json:"messages"`
}

type JoinScreenshareRequest struct {
	EventType string `json:"type"`
	User      string `json:"user"`
}

type TypingIndicator struct {
	EventType string `json:"type"`
	Channel   string `json:"channel"`
}

type EmoteListResponse struct {
	EventType string  `json:"type"`
	Emotes    []Emote `json:"emotes"`
}

type Emote struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type voiceClient struct {
	user   string
	stream *quic.Stream
	send   chan []byte
}

type screenshareClient struct {
	user    string
	stream  *quic.ReceiveStream
	viewers map[string]*quic.SendStream
	mu      sync.RWMutex
}

type Server struct {
	addr     string
	listener *quic.Listener
	db       *database.DB

	// Channel management
	voiceChannels      map[string]map[string]*voiceClient
	textChannels       map[string]bool
	eventStreams       map[string]*quic.Stream
	screenshareStreams map[string]*screenshareClient

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
		eventStreams:       make(map[string]*quic.Stream),
		screenshareStreams: make(map[string]*screenshareClient),
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

	go s.acceptUniStreams(conn)
	s.acceptBidiStreams(conn)
}

func (s *Server) acceptUniStreams(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptUniStream(context.Background())
		if err != nil {
			log.Printf("AcceptUniStream error: %v", err)
			return
		}
		log.Printf("Accepted unidirectional stream id: %d", stream.StreamID())
		s.routeUniStream(conn, stream)
	}
}

func (s *Server) routeUniStream(conn *quic.Conn, stream *quic.ReceiveStream) {
	switch stream.StreamID() {
	case 2:
		go s.handleScreenshareRecv(conn, stream)
	default:
		log.Printf("Unknown unidirectional stream id: %d", stream.StreamID())
		stream.CancelRead(0)
	}
}

func (s *Server) acceptBidiStreams(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("AcceptStream error: %v", err)
			return
		}
		s.routeBidiStream(conn, stream)
	}
}

func (s *Server) routeBidiStream(conn *quic.Conn, stream *quic.Stream) {
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

func (s *Server) handleScreenshareRecv(conn *quic.Conn, stream *quic.ReceiveStream) {
	connID := fmt.Sprintf("%p", conn)
	s.mu.RLock()
	username, authenticated := s.authenticatedConns[connID]
	s.mu.RUnlock()

	if !authenticated {
		log.Printf("Unauthenticated connection attempted to open screenshare stream")
		stream.CancelRead(0)
		return
	}

	client := &screenshareClient{
		user:    username,
		stream:  stream,
		viewers: make(map[string]*quic.SendStream),
	}

	s.mu.Lock()
	s.screenshareStreams[username] = client
	s.mu.Unlock()

	log.Printf("User %s started screensharing", username)

	defer func() {
		s.mu.Lock()
		for _, viewerStream := range client.viewers {
			_ = (*viewerStream).Close()
		}
		delete(s.screenshareStreams, username)
		s.mu.Unlock()
		stream.CancelRead(0)
		log.Printf("User %s stopped screensharing", username)
	}()

	buf := make([]byte, 8192)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			log.Printf("Read error from screenshare stream: %v", err)
			return
		}
		log.Printf("Received %d bytes from screenshare stream (user: %s)", n, username)

		client.mu.RLock()
		viewers := make([]*quic.SendStream, 0, len(client.viewers))
		for _, v := range client.viewers {
			viewers = append(viewers, v)
		}
		client.mu.RUnlock()

		for _, viewerStream := range viewers {
			_ = (*viewerStream).SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			if _, err := (*viewerStream).Write(buf[:n]); err != nil {
				log.Printf("Error writing to viewer stream: %v", err)
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
	challenge, err := s.sendAuthChallenge(connID, stream)
	if err != nil {
		return
	}

	username, pubKeyHex, err := s.readAndVerifyAuthResponse(connID, stream, challenge)
	if err != nil {
		return
	}

	if err := s.authenticateOrCreateUser(connID, stream, username, pubKeyHex); err != nil {
		return
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

func (s *Server) sendAuthChallenge(connID string, stream *quic.Stream) ([]byte, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		log.Printf("Failed to generate challenge: %v", err)
		_, _ = stream.Write([]byte("error:internal server error"))
		return nil, err
	}

	s.mu.Lock()
	s.pendingChallenges[connID] = challenge
	s.mu.Unlock()

	challengeHex := hex.EncodeToString(challenge)
	if _, err := stream.Write([]byte(challengeHex)); err != nil {
		log.Printf("Failed to send challenge: %v", err)
		return nil, err
	}

	return challenge, nil
}

func (s *Server) readAndVerifyAuthResponse(connID string, stream *quic.Stream, challenge []byte) (string, string, error) {
	buf := make([]byte, 8192)
	n, err := stream.Read(buf)
	if err != nil {
		log.Printf("Failed to read auth response: %v", err)
		s.cleanupChallenge(connID)
		return "", "", err
	}

	username, pubKeyHex, signatureHex, err := s.parseAuthResponse(string(buf[:n]))
	if err != nil {
		_, _ = stream.Write([]byte("error:" + err.Error()))
		s.cleanupChallenge(connID)
		return "", "", err
	}

	if err := s.verifySignature(pubKeyHex, signatureHex, challenge); err != nil {
		_, _ = stream.Write([]byte("error:" + err.Error()))
		s.cleanupChallenge(connID)
		return "", "", err
	}

	return username, pubKeyHex, nil
}

func (s *Server) parseAuthResponse(response string) (string, string, string, error) {
	parts := strings.SplitN(response, ":", 3)
	if len(parts) != 3 {
		log.Printf("Invalid auth response format: got %d parts, expected 3", len(parts))
		return "", "", "", errors.New("invalid format")
	}

	username := parts[0]
	if err := validateUsername(username); err != nil {
		log.Printf("Invalid username: %v", err)
		return "", "", "", err
	}

	return username, parts[1], parts[2], nil
}

func (s *Server) verifySignature(pubKeyHex, signatureHex string, challenge []byte) error {
	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		log.Printf("Invalid public key: %v", err)
		return errors.New("invalid public key")
	}

	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		log.Printf("Invalid signature: %v", err)
		return errors.New("invalid signature")
	}

	if !ed25519.Verify(ed25519.PublicKey(pubKey), challenge, signature) {
		log.Printf("Signature verification failed")
		return errors.New("authentication failed")
	}

	return nil
}

func (s *Server) authenticateOrCreateUser(connID string, stream *quic.Stream, username, pubKeyHex string) error {
	existingUser, userErr := s.db.GetUserByUsernameAndPublicKey(username, pubKeyHex)
	if userErr == nil {
		return s.handleExistingUser(connID, stream, existingUser, pubKeyHex)
	}
	return s.handleNewUser(connID, stream, username, pubKeyHex)
}

func (s *Server) handleExistingUser(connID string, stream *quic.Stream, user *database.User, pubKeyHex string) error {
	if !user.IsApproved {
		log.Printf("User %s not yet approved by admin", user.Username)
		_, _ = stream.Write([]byte("error:pending approval"))
		s.cleanupChallenge(connID)
		return errors.New("pending approval")
	}
	if err := s.db.UpdateLastAuth(pubKeyHex); err != nil {
		log.Printf("Failed to update last auth: %v", err)
	}
	return nil
}

func (s *Server) handleNewUser(connID string, stream *quic.Stream, username, pubKeyHex string) error {
	isAvailable, err := s.db.IsUsernameAvailable(username)
	if err != nil {
		log.Printf("Failed to check username availability: %v", err)
		_, _ = stream.Write([]byte("error:internal server error"))
		s.cleanupChallenge(connID)
		return err
	}

	if !isAvailable {
		log.Printf("Username already taken: %s", username)
		_, _ = stream.Write([]byte("error:username already taken"))
		s.cleanupChallenge(connID)
		return errors.New("username already taken")
	}

	isAdmin := s.checkAndSetFirstAdmin(username)

	if err := s.db.CreateUser(username, pubKeyHex, isAdmin); err != nil {
		log.Printf("Failed to create user: %v", err)
		_, _ = stream.Write([]byte("error:failed to create user"))
		s.cleanupChallenge(connID)
		return err
	}

	if !isAdmin {
		log.Printf("New user %s created, pending admin approval", username)
		_, _ = stream.Write([]byte("error:pending approval"))
		s.cleanupChallenge(connID)
		return errors.New("pending approval")
	}

	return nil
}

func (s *Server) checkAndSetFirstAdmin(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	isAdmin := !s.hasInitialAdmin
	if isAdmin {
		s.hasInitialAdmin = true
		log.Printf("Creating first user as admin: %s", username)
	}
	return isAdmin
}

func (s *Server) cleanupChallenge(connID string) {
	s.mu.Lock()
	delete(s.pendingChallenges, connID)
	s.mu.Unlock()
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

	connID := fmt.Sprintf("%p", conn)
	if !s.authenticateEventStream(connID, stream) {
		return
	}

	s.mu.Lock()
	s.eventStreams[connID] = stream
	s.mu.Unlock()

	if err := s.sendServerInfo(stream); err != nil {
		return
	}

	s.processEventMessages(conn, stream)
}

func (s *Server) authenticateEventStream(connID string, stream *quic.Stream) bool {
	s.mu.RLock()
	_, authenticated := s.authenticatedConns[connID]
	s.mu.RUnlock()

	if !authenticated {
		log.Printf("Unauthenticated connection attempted to access event stream")
		_, _ = stream.Write([]byte("error:not authenticated"))
		return false
	}
	return true
}

func (s *Server) sendServerInfo(stream *quic.Stream) error {
	channelNames, err := s.db.GetAllChannelNames()
	if err != nil {
		log.Printf("Error getting channel names: %v", err)
		return err
	}

	data := &ServerInfo{
		EventType: "ServerInfo",
		Channels:  channelNames,
	}
	encjson, err := json.Marshal(data)
	if err != nil {
		log.Println(err)
		return err
	}
	encjson = append(encjson, '\n')
	if _, err := stream.Write(encjson); err != nil {
		log.Printf("Error writing server info: %v", err)
		return err
	}
	return nil
}

func (s *Server) processEventMessages(conn *quic.Conn, stream *quic.Stream) {
	buf := make([]byte, 4096)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}

		message := string(buf[:n])
		log.Printf("Read %d bytes from EVENT stream: %s", n, message)

		if message == "hb" {
			continue
		}

		s.routeEventMessage(conn, stream, buf[:n])
	}
}

func (s *Server) routeEventMessage(conn *quic.Conn, stream *quic.Stream, data []byte) {
	var envelope struct {
		EventType string `json:"type"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		log.Printf("routeEventMessage: unmarshal error: %v", err)
		return
	}

	switch envelope.EventType {
	case "admin_request":
		var adminReq AdminRequest
		_ = json.Unmarshal(data, &adminReq)
		s.handleAdminRequest(conn, stream, &adminReq)
	case "Message":
		var msg IncomingMessage
		_ = json.Unmarshal(data, &msg)
		s.handleTextMessage(conn, &msg)
	case "history_request":
		var historyReq MessageHistoryRequest
		_ = json.Unmarshal(data, &historyReq)
		s.handleMessageHistory(conn, stream, &historyReq)
	case "joinScreenshare":
		var joinReq JoinScreenshareRequest
		_ = json.Unmarshal(data, &joinReq)
		s.handleJoinScreenshare(conn, &joinReq)
	case "typing_indicator":
		var typingInd TypingIndicator
		_ = json.Unmarshal(data, &typingInd)
		s.handleTypingIndicator(conn, &typingInd)
	case "emote_list_request":
		s.handleEmoteListRequest(conn, stream)
	default:
		log.Printf("routeEventMessage: unknown event type: %s", envelope.EventType)
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

func (s *Server) handleJoinScreenshare(conn *quic.Conn, joinReq *JoinScreenshareRequest) {
	connID := fmt.Sprintf("%p", conn)
	s.mu.RLock()
	viewerUsername, authenticated := s.authenticatedConns[connID]
	s.mu.RUnlock()

	if !authenticated {
		log.Printf("Unauthenticated connection attempted to join screenshare")
		return
	}

	targetUser := joinReq.User
	log.Printf("User %s wants to join %s's screenshare", viewerUsername, targetUser)

	s.mu.RLock()
	screenshareClient, exists := s.screenshareStreams[targetUser]
	s.mu.RUnlock()

	if !exists {
		log.Printf("User %s is not screensharing", targetUser)
		return
	}

	sendStream, err := conn.OpenUniStreamSync(context.Background())
	if err != nil {
		log.Printf("Failed to open uni stream for viewer %s: %v", viewerUsername, err)
		return
	}

	screenshareClient.mu.Lock()
	screenshareClient.viewers[viewerUsername] = sendStream
	screenshareClient.mu.Unlock()

	log.Printf("User %s is now viewing %s's screenshare", viewerUsername, targetUser)

	go func() {
		<-conn.Context().Done()
		screenshareClient.mu.Lock()
		delete(screenshareClient.viewers, viewerUsername)
		screenshareClient.mu.Unlock()
		_ = sendStream.Close()
		log.Printf("User %s stopped viewing %s's screenshare", viewerUsername, targetUser)
	}()
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
		Data:      map[string]any{"user_id": adminReq.UserID, "status": "approved"},
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

	if err := stream.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Printf("Error setting write deadline: %v", err)
		return
	}

	if _, err := stream.Write(jsonData); err != nil {
		log.Printf("Error writing admin response: %v", err)
	}

	_ = stream.SetWriteDeadline(time.Time{})
}

func (s *Server) handleVoiceStream(conn *quic.Conn, stream *quic.Stream) {
	connID := fmt.Sprintf("%p", conn)
	username, err := s.authenticateVoiceStream(connID, stream)
	if err != nil {
		return
	}

	channel, err := s.readChannelName(stream)
	if err != nil {
		return
	}

	if err := s.joinVoiceChannel(channel, username, stream); err != nil {
		return
	}

	s.handleVoicePackets(stream, channel, username)
}

func (s *Server) authenticateVoiceStream(connID string, stream *quic.Stream) (string, error) {
	s.mu.RLock()
	username, authenticated := s.authenticatedConns[connID]
	s.mu.RUnlock()

	if !authenticated {
		log.Printf("Unauthenticated connection attempted to access voice stream")
		_, _ = stream.Write([]byte("error:not authenticated"))
		_ = stream.Close()
		return "", errors.New("not authenticated")
	}
	return username, nil
}

func (s *Server) readChannelName(stream *quic.Stream) (string, error) {
	buf := make([]byte, 8192)
	n, err := stream.Read(buf)
	if err != nil {
		log.Printf("Read error: %v", err)
		return "", err
	}
	log.Printf("Read %d bytes from voice stream", n)
	channel := string(buf[:n])
	log.Printf("Received from voice stream: %s", channel)
	return channel, nil
}

func (s *Server) joinVoiceChannel(channel, username string, stream *quic.Stream) error {
	s.mu.RLock()
	_, exists := s.voiceChannels[channel]
	s.mu.RUnlock()

	if !exists {
		log.Printf("Voice channel not found: %s", channel)
		_, _ = stream.Write([]byte("error:channel not found"))
		_ = stream.Close()
		return errors.New("channel not found")
	}

	s.addStreamToChannel(channel, username, stream)
	log.Printf("User %s joined %s", username, channel)
	s.sendOkMessage(stream)
	return nil
}

func (s *Server) handleVoicePackets(stream *quic.Stream, channel, username string) {
	buf := make([]byte, 8192)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}
		log.Printf("Read %d bytes from voice stream", n)

		combined := s.createVoicePacket(username, buf[:n])
		s.broadcastVoiceToChannel(channel, username, combined)
	}
}

func (s *Server) createVoicePacket(username string, payload []byte) []byte {
	usernameBytes := []byte(username)
	delimiter := []byte(":")
	combined := make([]byte, len(usernameBytes)+len(delimiter)+len(payload))
	copy(combined, usernameBytes)
	copy(combined[len(usernameBytes):], delimiter)
	copy(combined[len(usernameBytes)+len(delimiter):], payload)
	return combined
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
	if packetLen > math.MaxUint32 {
		log.Printf("broadcastVoiceToChannel: packet too large: %d bytes", packetLen)
		return
	}
	packet := make([]byte, 4+packetLen)
	binary.LittleEndian.PutUint32(packet[:4], uint32(packetLen))
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
		send:   make(chan []byte, 32),
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
	delete(s.eventStreams, connID)
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

func (s *Server) broadcastToEventStreams(data []byte) {
	s.broadcastToEventStreamsExcept("", data)
}

func (s *Server) broadcastToEventStreamsExcept(excludeConnID string, data []byte) {
	s.mu.RLock()
	streams := make(map[string]*quic.Stream, len(s.eventStreams))
	for id, stream := range s.eventStreams {
		streams[id] = stream
	}
	s.mu.RUnlock()
	for connID, stream := range streams {
		if connID == excludeConnID {
			continue
		}
		_ = (*stream).SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := (*stream).Write(data); err != nil {
			log.Printf("broadcastToEventStreams: write error: %v", err)
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
	s.broadcastToEventStreams(data)
}

func (s *Server) handleTypingIndicator(conn *quic.Conn, ind *TypingIndicator) {
	connID := fmt.Sprintf("%p", conn)
	s.mu.RLock()
	username, authenticated := s.authenticatedConns[connID]
	s.mu.RUnlock()

	if !authenticated {
		log.Printf("Unauthenticated connection sent typing indicator")
		return
	}

	data, err := json.Marshal(UserAction{
		EventType: "typing_indicator",
		User:      username,
		Channel:   ind.Channel,
	})
	if err != nil {
		log.Printf("handleTypingIndicator: marshal error: %v", err)
		return
	}
	data = append(data, '\n')
	s.broadcastToEventStreamsExcept(connID, data)
}

func (s *Server) handleTextMessage(conn *quic.Conn, msg *IncomingMessage) {
	connID := fmt.Sprintf("%p", conn)
	s.mu.RLock()
	username, authenticated := s.authenticatedConns[connID]
	s.mu.RUnlock()

	if !authenticated {
		log.Printf("Unauthenticated connection attempted to send message")
		return
	}

	if msg.Content == "" {
		log.Printf("Empty message content from user %s", username)
		return
	}

	s.mu.RLock()
	_, exists := s.textChannels[msg.Channel]
	s.mu.RUnlock()

	if !exists {
		log.Printf("Text channel not found: %s", msg.Channel)
		return
	}

	savedMsg, err := s.db.SaveMessage(msg.Channel, username, msg.Content, msg.Compressed)
	if err != nil {
		log.Printf("Failed to save message: %v", err)
		return
	}

	outgoing := OutgoingMessage{
		EventType:  "Message",
		Channel:    savedMsg.Channel,
		Content:    savedMsg.Content,
		Compressed: savedMsg.Compressed,
		User:       savedMsg.User,
		Timestamp:  savedMsg.CreatedAt,
		ID:         savedMsg.ID,
	}

	data, err := json.Marshal(outgoing)
	if err != nil {
		log.Printf("Failed to marshal outgoing message: %v", err)
		return
	}
	data = append(data, '\n')
	s.broadcastToEventStreams(data)

	log.Printf("Message from %s in %s (id=%d)", username, msg.Channel, savedMsg.ID)
}

func (s *Server) handleMessageHistory(conn *quic.Conn, stream *quic.Stream, req *MessageHistoryRequest) {
	connID := fmt.Sprintf("%p", conn)
	s.mu.RLock()
	_, authenticated := s.authenticatedConns[connID]
	s.mu.RUnlock()

	if !authenticated {
		log.Printf("Unauthenticated connection attempted to request message history")
		return
	}

	if req.Channel == "" {
		log.Printf("Empty channel in history request")
		return
	}

	messages, err := s.db.GetMessages(req.Channel, req.Limit, req.Before)
	if err != nil {
		log.Printf("Failed to get messages for channel %s: %v", req.Channel, err)
		return
	}

	outMsgs := make([]OutgoingMessage, len(messages))
	for i, m := range messages {
		outMsgs[i] = OutgoingMessage{
			EventType:  "Message",
			Channel:    m.Channel,
			Content:    m.Content,
			Compressed: m.Compressed,
			User:       m.User,
			Timestamp:  m.CreatedAt,
			ID:         m.ID,
		}
	}

	response := MessageHistoryResponse{
		EventType: "history_response",
		Request:   "get_messages",
		Channel:   req.Channel,
		Messages:  outMsgs,
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal history response: %v", err)
		return
	}
	jsonData = append(jsonData, '\n')

	if err := stream.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Printf("Error setting write deadline for history response: %v", err)
		return
	}
	if _, err := stream.Write(jsonData); err != nil {
		log.Printf("Error writing history response: %v", err)
	}
	_ = stream.SetWriteDeadline(time.Time{})

	log.Printf("Sent %d messages history for channel %s", len(outMsgs), req.Channel)
}

func (s *Server) handleEmoteListRequest(conn *quic.Conn, stream *quic.Stream) {
	connID := fmt.Sprintf("%p", conn)
	s.mu.RLock()
	_, authenticated := s.authenticatedConns[connID]
	s.mu.RUnlock()

	if !authenticated {
		log.Printf("Unauthenticated connection requested emote list")
		return
	}

	emotesDir := filepath.Join(GetDataDir(), "emotes")
	emoteFS := os.DirFS(emotesDir)
	entries, err := fs.ReadDir(emoteFS, ".")
	if err != nil {
		log.Printf("Failed to read emotes directory: %v", err)
		s.sendEmoteListResponse(stream, nil)
		return
	}

	var emotes []Emote
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		ext := filepath.Ext(name)
		emoteName := strings.TrimSuffix(name, ext)

		switch strings.ToLower(ext) {
		case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp":
		default:
			continue
		}

		data, err := fs.ReadFile(emoteFS, name)
		if err != nil {
			log.Printf("Failed to read emote file %s: %v", name, err)
			continue
		}

		emotes = append(emotes, Emote{
			Name: emoteName,
			Data: base64.StdEncoding.EncodeToString(data),
		})
	}

	s.sendEmoteListResponse(stream, emotes)
	log.Printf("Sent %d emotes to client", len(emotes))
}

func (s *Server) sendEmoteListResponse(stream *quic.Stream, emotes []Emote) {
	if emotes == nil {
		emotes = []Emote{}
	}

	response := EmoteListResponse{
		EventType: "emote_list_response",
		Emotes:    emotes,
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal emote list response: %v", err)
		return
	}
	jsonData = append(jsonData, '\n')

	if err := stream.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("Error setting write deadline for emote response: %v", err)
		return
	}
	if _, err := stream.Write(jsonData); err != nil {
		log.Printf("Error writing emote list response: %v", err)
	}
	_ = stream.SetWriteDeadline(time.Time{})
}
