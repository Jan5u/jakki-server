package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/Jan5u/jakki-server/database"
	"github.com/quic-go/quic-go"
)

type ServerInfo struct {
	EventType string   `json:"type"`
	Channels  []string `json:"channels"`
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

	// Voice channel management
	channels         map[string]map[string]*voiceClient
	channelUserCount map[string]int
	eventStreams     []*quic.Stream
	mu               sync.RWMutex
}

func NewServer(addr string, db *database.DB) *Server {
	return &Server{
		addr:             addr,
		db:               db,
		channels:         make(map[string]map[string]*voiceClient),
		channelUserCount: make(map[string]int),
		eventStreams:     make([]*quic.Stream, 0),
	}
}

func (s *Server) RunServer() error {
	listener, err := quic.ListenAddr(s.addr, createTLSConfig(), nil)
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
			if _, exists := s.channels[ch.Name]; !exists {
				s.channels[ch.Name] = make(map[string]*voiceClient)
			}
			s.mu.Unlock()
			log.Printf("Loaded voice channel: %s", ch.Name)
		} else {
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

func createTLSConfig() *tls.Config {
	dataDir := GetDataDir()
	certPath := filepath.Join(dataDir, "cert.pem")
	keyPath := filepath.Join(dataDir, "key.pem")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("Failed to createTLSConfig: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"jakki"},
		ServerName:   "jakki",
		MinVersion:   tls.VersionTLS12,
	}
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
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("AcceptStream error: %v", err)
			return
		}
		switch stream.StreamID() {
		case 0:
			go s.handleEventStream(stream)
		case 4:
			go s.handleVoiceStream(stream)
		default:
			log.Printf("Unknown stream id: %d", stream.StreamID())
			if err := stream.Close(); err != nil {
				log.Printf("Error closing unknown stream: %v", err)
			}
		}
	}
}

func (s *Server) handleEventStream(stream *quic.Stream) {
	defer func() {
		if err := stream.Close(); err != nil {
			log.Printf("Error closing event stream: %v", err)
		}
	}()
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

		// only used for heartbeat for now
		log.Printf("Read %d bytes from EVENT stream", n)
	}
}

func (s *Server) handleVoiceStream(stream *quic.Stream) {
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
	_, exists := s.channels[channel]
	s.mu.RUnlock()

	if !exists {
		log.Printf("Voice channel not found: %s", channel)
		_, _ = stream.Write([]byte("error:channel not found"))
		_ = stream.Close()
		return
	}

	s.channelUserCount[channel]++
	username := "user" + strconv.Itoa(s.channelUserCount[channel])

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
	channelStreams, exists := s.channels[channel]
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
	if _, ok := s.channels[channel]; !ok {
		s.channels[channel] = make(map[string]*voiceClient)
	}
	s.channels[channel][user] = vc
	s.mu.Unlock()

	log.Printf("Added stream for user %s to channel %s", user, channel)

	// start writer goroutine
	go s.voiceWriterLoop(channel, vc)

	// send event that user has joined this channel
	joinEvent := UserAction{
		EventType: "UserJoin",
		User:      user,
		Channel:   channel,
	}
	s.broadcastEvent(joinEvent)
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
	if channelStreams, ok := s.channels[channel]; ok {
		if vc, exists := channelStreams[user]; exists {
			delete(channelStreams, user)
			_ = vc.stream.Close()
			close(vc.send)
			log.Printf("Removed voice client user=%s from channel=%s", user, channel)
		}
		if len(channelStreams) == 0 {
			delete(s.channels, channel)
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
