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
}

func Register(hostname, sessionId, password, udpAddr string, create bool) ([]PeerAddr, error) {
	if hostname != "" && hostname[len(hostname)-1] == '/' {
		hostname = hostname[:len(hostname)-1]
	}
	if strings.TrimSpace(hostname) == "" {
		hostname = "https://rendezvous.enzogp.dev"
	}
	if !strings.HasPrefix(hostname, "http://") && !strings.HasPrefix(hostname, "https://") {
		hostname = "https://" + hostname
	}
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

	// server returns {"peers": [{"ip": "...", "local_addr": "..."}]}
	var respBody struct {
		Peers []struct {
			IP        string `json:"ip"`
			LocalAddr string `json:"local_addr"`
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
	if hostname != "" && hostname[len(hostname)-1] == '/' {
		hostname = hostname[:len(hostname)-1]
	}
	if strings.TrimSpace(hostname) == "" {
		hostname = "https://rendezvous.enzogp.dev"
	}
	if !strings.HasPrefix(hostname, "http://") && !strings.HasPrefix(hostname, "https://") {
		hostname = "https://" + hostname
	}

	var endpoint string
	if password != "" {
		endpoint = fmt.Sprintf("%s/join_session/%s/stream?password=%s&udp_addr=%s",
			hostname, sessionId, url.QueryEscape(password), url.QueryEscape(myAddr))
	} else {
		endpoint = fmt.Sprintf("%s/session/%s/stream?udp_addr=%s",
			hostname, sessionId, url.QueryEscape(myAddr))
	}

	ch := make(chan PeerAddr, 10)
	go func() {
		defer close(ch)

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

			req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
			if err != nil {
				cancel()
				return
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
				}
				if err := json.Unmarshal([]byte(data), &peer); err != nil {
					continue
				}
				select {
				case ch <- PeerAddr{Public: peer.IP, Local: peer.LocalAddr}:
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
	if hostname != "" && hostname[len(hostname)-1] == '/' {
		hostname = hostname[:len(hostname)-1]
	}
	if strings.TrimSpace(hostname) == "" {
		hostname = "https://rendezvous.enzogp.dev"
	}
	if !strings.HasPrefix(hostname, "http://") && !strings.HasPrefix(hostname, "https://") {
		hostname = "https://" + hostname
	}
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
