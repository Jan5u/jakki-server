package main

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

const addr = "0.0.0.0:7777"

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

var (
	db               *database.DB
	channels         = make(map[string]map[string]*voiceClient)
	channelUserCount = make(map[string]int)
	eventStreams     []*quic.Stream
	mu               sync.RWMutex
)

func loadChannelsFromDB() error {
	allChannels, err := db.GetAllChannels()
	if err != nil {
		return err
	}

	for _, ch := range allChannels {
		if ch.Type == database.ChannelTypeVoice {
			mu.Lock()
			if _, exists := channels[ch.Name]; !exists {
				channels[ch.Name] = make(map[string]*voiceClient)
			}
			mu.Unlock()
			log.Printf("Loaded voice channel: %s", ch.Name)
		} else {
			log.Printf("Loaded text channel: %s", ch.Name)
		}
	}

	return nil
}

func main() {
	dataDir := getDataDir()
	var err error
	db, err = database.New(dataDir)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	if err := loadChannelsFromDB(); err != nil {
		_ = db.Close()
		log.Fatalf("Failed to load channels: %v", err)
	}

	defer func() { _ = db.Close() }()

	listener, err := quic.ListenAddr(addr, createTLSConfig(), nil)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("Error closing listener: %v", err)
		}
	}()

	log.Printf("Listening on %s\n", addr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Listener error: %v", err)
			return
		}
		go handleConnection(conn)
	}
}

func createTLSConfig() *tls.Config {
	dataDir := getDataDir()
	certPath := filepath.Join(dataDir, "cert.pem")
	keyPath := filepath.Join(dataDir, "key.pem")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"jakki"},
		ServerName:   "jakki",
		MinVersion:   tls.VersionTLS12,
	}
}

func getDataDir() string {
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

func handleConnection(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("AcceptStream error: %v", err)
			return
		}
		switch stream.StreamID() {
		case 0:
			go handleEventStream(stream)
		case 4:
			go handleVoiceStream(stream)
		default:
			log.Printf("Unknown stream id: %d", stream.StreamID())
			if err := stream.Close(); err != nil {
				log.Printf("Error closing unknown stream: %v", err)
			}
		}
	}
}

func handleEventStream(stream *quic.Stream) {
	defer func() {
		if err := stream.Close(); err != nil {
			log.Printf("Error closing event stream: %v", err)
		}
	}()
	mu.Lock()
	eventStreams = append(eventStreams, stream)
	mu.Unlock()

	// Send server info with channels from database
	channelNames, err := db.GetAllChannelNames()
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
	buf := make([]byte, 7500000)
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

func handleVoiceStream(stream *quic.Stream) {
	buf := make([]byte, 7500000)

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
	mu.RLock()
	_, exists := channels[channel]
	mu.RUnlock()

	if !exists {
		log.Printf("Voice channel not found: %s", channel)
		_, _ = stream.Write([]byte("error:channel not found"))
		_ = stream.Close()
		return
	}

	channelUserCount[channel]++
	username := "user" + strconv.Itoa(channelUserCount[channel])

	addStreamToChannel(channel, username, stream)
	log.Printf("User %s joined %s", username, channel)

	// send ok for voice packets
	sendOkMessage(stream)

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
		broadcastVoiceToChannel(channel, username, combined)
	}
}

func sendOkMessage(stream *quic.Stream) {
	_, err := stream.Write([]byte("ok"))
	if err != nil {
		log.Printf("sendOkMessage: write error: %v", err)
	}
}

func broadcastVoiceToChannel(channel, sender string, data []byte) {
	// add data length to the packet
	packetLen := len(data)
	packet := make([]byte, 4+packetLen)
	packet[0] = byte(packetLen)
	packet[1] = byte(packetLen >> 8)
	packet[2] = byte(packetLen >> 16)
	packet[3] = byte(packetLen >> 24)
	copy(packet[4:], data)

	mu.RLock()
	channelStreams, exists := channels[channel]
	if !exists {
		mu.RUnlock()
		return
	}

	clients := make([]*voiceClient, 0, len(channelStreams))
	for user, c := range channelStreams {
		if user == sender {
			continue
		}
		clients = append(clients, c)
	}
	mu.RUnlock()

	for _, c := range clients {
		select {
		case c.send <- packet:
			// queued
		default:
			log.Printf("broadcastVoice: dropping packet for slow user %s", c.user)
		}
	}
}

func addStreamToChannel(channel, user string, stream *quic.Stream) *voiceClient {
	vc := &voiceClient{
		user:   user,
		stream: stream,
		send:   make(chan []byte, 32), // small buffer; tune as needed
	}

	mu.Lock()
	if _, ok := channels[channel]; !ok {
		channels[channel] = make(map[string]*voiceClient)
	}
	channels[channel][user] = vc
	mu.Unlock()

	log.Printf("Added stream for user %s to channel %s", user, channel)

	// start writer goroutine
	go voiceWriterLoop(channel, vc)

	// send event that user has joined this channel
	joinEvent := UserAction{
		EventType: "UserJoin",
		User:      user,
		Channel:   channel,
	}
	broadcastEvent(joinEvent)
	return vc
}

func voiceWriterLoop(channel string, vc *voiceClient) {
	for msg := range vc.send {
		// set a write deadline so quic-go unblocks quickly for dead peers
		_ = vc.stream.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := vc.stream.Write(msg); err != nil {
			log.Printf("voiceWriterLoop: write error user=%s err=%v", vc.user, err)
			removeVoiceClient(channel, vc.user)
			return
		}
	}

	removeVoiceClient(channel, vc.user)
}

func removeVoiceClient(channel, user string) {
	mu.Lock()
	defer mu.Unlock()
	if channelStreams, ok := channels[channel]; ok {
		if vc, exists := channelStreams[user]; exists {
			delete(channelStreams, user)
			_ = vc.stream.Close()
			close(vc.send)
			log.Printf("Removed voice client user=%s from channel=%s", user, channel)
		}
		if len(channelStreams) == 0 {
			delete(channels, channel)
		}
	}
}

func broadcastEvent(event UserAction) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("broadcastEvent: marshal error: %v", err)
		return
	}
	data = append(data, '\n')
	mu.RLock()
	streams := make([]*quic.Stream, len(eventStreams))
	copy(streams, eventStreams)
	mu.RUnlock()
	for _, stream := range streams {
		_ = stream.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := stream.Write(data); err != nil {
			log.Printf("broadcastEvent: write error: %v", err)
		}
	}
}
