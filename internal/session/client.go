package session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
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
		if createRes["error"] != "" {
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
