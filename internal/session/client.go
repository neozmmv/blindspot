package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type PeerAddr struct {
	Public string
	Local  string
	PubKey string // base64-encoded Noise static public key, distributed by the rendezvous
}

const defaultRendezvous = "https://rendezvous.enzogp.dev"

// normalizeScheme trims a trailing slash, applies the default host when empty, and
// defaults a bare host to https://. It does NOT enforce the http:// policy — that
// is NormalizeHostname's job so that tests/insecure callers can still pass http://.
func normalizeScheme(hostname string) string {
	hostname = strings.TrimSpace(hostname)
	if hostname != "" && hostname[len(hostname)-1] == '/' {
		hostname = hostname[:len(hostname)-1]
	}
	if hostname == "" {
		return defaultRendezvous
	}
	if !strings.HasPrefix(hostname, "http://") && !strings.HasPrefix(hostname, "https://") {
		hostname = "https://" + hostname
	}
	return hostname
}

// NormalizeHostname resolves the rendezvous URL and enforces transport security:
// a plaintext http:// rendezvous is rejected unless the caller explicitly opts in
// with insecure=true. The CLI calls this once so the password (and the Noise
// handshake bootstrap) never travel over an unauthenticated channel by accident.
func NormalizeHostname(hostname string, insecure bool) (string, error) {
	hostname = normalizeScheme(hostname)
	if strings.HasPrefix(hostname, "http://") && !insecure {
		return "", fmt.Errorf("refusing plaintext http:// rendezvous %q; use https:// or pass --insecure", hostname)
	}
	return hostname, nil
}

func Register(hostname, sessionId, password, udpAddr, pubKey string, create bool) ([]PeerAddr, error) {
	hostname = normalizeScheme(hostname)
	if strings.TrimSpace(sessionId) == "" {
		return nil, fmt.Errorf("sessionId is required")
	}

	if password != "" && create {
		createBody, _ := json.Marshal(map[string]string{
			"id":       sessionId,
			"password": password,
		})
		res, err := http.Post(fmt.Sprintf("%s/create_session", hostname), "application/json", bytes.NewBuffer(createBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create session: %w", err)
		}
		defer res.Body.Close()
		var createRes map[string]string
		json.NewDecoder(res.Body).Decode(&createRes)
		if createRes["error"] != "" && createRes["error"] != "session already exists" {
			return nil, fmt.Errorf("failed to create session: %s", createRes["error"])
		}
	}

	parts := strings.Split(udpAddr, ":")
	port, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse UDP address: %w", err)
	}
	localAddr := GetLocalAddr(port)

	body := map[string]string{
		"udp_addr":   udpAddr,
		"local_addr": localAddr,
		"pub_key":    pubKey,
	}
	if password != "" {
		body["password"] = password
	}
	bodyJson, _ := json.Marshal(body)

	var endpoint string
	if password != "" {
		endpoint = fmt.Sprintf("%s/join_session/%s", hostname, sessionId)
	} else {
		endpoint = fmt.Sprintf("%s/session/%s", hostname, sessionId)
	}

	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(bodyJson))
	if err != nil {
		return nil, fmt.Errorf("failed to register: %w", err)
	}
	defer resp.Body.Close()

	// server returns {"peers": [{"ip": "...", "local_addr": "...", "pub_key": "..."}]}
	var respBody struct {
		Peers []struct {
			IP        string `json:"ip"`
			LocalAddr string `json:"local_addr"`
			PubKey    string `json:"pub_key"`
		} `json:"peers"`
		Error string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&respBody)
	if respBody.Error != "" {
		return nil, fmt.Errorf("error from server: %s", respBody.Error)
	}

	peers := make([]PeerAddr, len(respBody.Peers))
	for i, p := range respBody.Peers {
		peers[i] = PeerAddr{
			Public: p.IP,
			Local:  p.LocalAddr,
			PubKey: p.PubKey,
		}
	}
	return peers, nil
}

func GetLocalAddr(remotePort int) string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.IsPrivate() && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				return fmt.Sprintf("%s:%d", ipnet.IP.String(), remotePort)
			}
		}
	}
	return ""
}

// StreamPeers opens an SSE connection to the rendezvous server and returns a channel
// that emits peers as they join the session (including peers already present).
// The stream closes when quit is closed.
func StreamPeers(hostname, sessionId, password, myAddr string, quit <-chan struct{}) <-chan PeerAddr {
	hostname = normalizeScheme(hostname)

	var endpoint, legacyEndpoint string
	if password != "" {
		// The password goes in the Authorization header, never the query string:
		// query strings leak into server access logs, proxies, and browser history.
		endpoint = fmt.Sprintf("%s/join_session/%s/stream?udp_addr=%s",
			hostname, sessionId, url.QueryEscape(myAddr))
		// Compatibility for rendezvous deployments that still authenticate password
		// streams via the legacy password query parameter.
		legacyEndpoint = fmt.Sprintf("%s/join_session/%s/stream?password=%s&udp_addr=%s",
			hostname, sessionId, url.QueryEscape(password), url.QueryEscape(myAddr))
	} else {
		endpoint = fmt.Sprintf("%s/session/%s/stream?udp_addr=%s",
			hostname, sessionId, url.QueryEscape(myAddr))
	}

	ch := make(chan PeerAddr, 10)
	go func() {
		defer close(ch)

		useLegacyQuery := false
		for {
			select {
			case <-quit:
				return
			default:
			}

			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				select {
				case <-quit:
					cancel()
				case <-ctx.Done():
				}
			}()

			streamURL := endpoint
			if useLegacyQuery {
				streamURL = legacyEndpoint
			}
			req, err := http.NewRequestWithContext(ctx, "GET", streamURL, nil)
			if err != nil {
				cancel()
				return
			}
			if password != "" && !useLegacyQuery {
				req.Header.Set("Authorization", "Bearer "+password)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				cancel()
				select {
				case <-quit:
					return
				case <-time.After(5 * time.Second):
					continue
				}
			}
			if password != "" && !useLegacyQuery && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
				resp.Body.Close()
				cancel()
				useLegacyQuery = true
				continue
			}
			if password != "" && !useLegacyQuery && !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
				resp.Body.Close()
				cancel()
				useLegacyQuery = true
				continue
			}

			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				if scanner.Err() != nil {
					break
				}
				line := scanner.Text()
				if !strings.HasPrefix(line, "data:") {
					continue
				}
				data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				var peer struct {
					IP        string `json:"ip"`
					LocalAddr string `json:"local_addr"`
					PubKey    string `json:"pub_key"`
				}
				if err := json.Unmarshal([]byte(data), &peer); err != nil {
					continue
				}
				select {
				case ch <- PeerAddr{Public: peer.IP, Local: peer.LocalAddr, PubKey: peer.PubKey}:
				case <-quit:
					resp.Body.Close()
					cancel()
					return
				}
			}
			resp.Body.Close()
			cancel()

			select {
			case <-quit:
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
	return ch
}

func Leave(hostname, sessionId, password, udpAddr string) {
	hostname = normalizeScheme(hostname)
	body := map[string]string{"udp_addr": udpAddr}
	if password != "" {
		body["password"] = password
	}
	bodyJson, _ := json.Marshal(body)
	var endpoint string
	if password != "" {
		endpoint = fmt.Sprintf("%s/join_session/%s/leave", hostname, sessionId)
	} else {
		endpoint = fmt.Sprintf("%s/session/%s/leave", hostname, sessionId)
	}
	http.Post(endpoint, "application/json", bytes.NewBuffer(bodyJson))
}
