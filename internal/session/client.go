package session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func Register(hostname, sessionId, password, udpAddr string, create bool) (string, error) {
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
		return "", fmt.Errorf("sessionId is required")
	}

	// creates session if create is true and password is provided, otherwise it will just try to join the session (which will fail if the session doesn't exist or password is wrong)
	if password != "" && create {
		createBody, _ := json.Marshal(map[string]string{
			"id":       sessionId,
			"password": password,
		})
		res, err := http.Post(fmt.Sprintf("%s/create_session", hostname), "application/json", bytes.NewBuffer(createBody))
		if err != nil {
			return "", fmt.Errorf("failed to create session: %w", err)
		}
		defer res.Body.Close()
		var createRes map[string]string
		json.NewDecoder(res.Body).Decode(&createRes)
		if createRes["error"] != "" {
			return "", fmt.Errorf("failed to create session: %s", createRes["error"])
		}
	}

	// registers the session and gets the peer's public address
	body := map[string]string{"udp_addr": udpAddr}
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
		return "", fmt.Errorf("failed to register: %w", err)
	}
	defer resp.Body.Close()

	var respBody map[string]string
	json.NewDecoder(resp.Body).Decode(&respBody)
	if respBody["error"] != "" {
		return "", fmt.Errorf("error from server: %s", respBody["error"])
	}

	return respBody["peer"], nil
}
