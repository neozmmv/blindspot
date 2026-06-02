package network

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"time"
)

var lastSeen time.Time

func punchHole(conn *net.UDPConn, peerAddr *net.UDPAddr) {
	for i := 0; i < 50; i++ {
		conn.WriteToUDP([]byte("punch"), peerAddr)
		time.Sleep(100 * time.Millisecond)
	}
}

func readFromPeer(conn *net.UDPConn) {
	buf := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error reading from peer: ", err)
			continue
		}
		if string(buf[:n]) == "punch" {
			continue
		}
		if string(buf[:n]) == "keepalive" {
			lastSeen = time.Now()
			continue
		}
		fmt.Printf("Received message from %s: %s\n", addr.String(), string(buf[:n]))
	}
}

func sendToPeer(conn *net.UDPConn, peerAddr *net.UDPAddr) {
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Err() != nil {
		fmt.Println("Error reading from stdin: ", scanner.Err())
		return
	}
	for scanner.Scan() {
		conn.WriteToUDP([]byte(scanner.Text()), peerAddr)
	}
}

func waitForPunch(conn *net.UDPConn, connected chan struct{}) {
	// waits for punch and closes the connected channel when it receives a punch
	buf := make([]byte, 1024)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error reading from peer: ", err)
			continue
		}
		if string(buf[:n]) == "punch" {
			close(connected)
			return
		}
	}
}

func keepAlive(conn *net.UDPConn, peerAddr *net.UDPAddr) {
	interval := 10 * time.Second
	for {
		time.Sleep(interval)
		conn.WriteToUDP([]byte("keepalive"), peerAddr)
	}
}

func watchConnection() {
	// if no keepalive received for 30 seconds, assume connection is dead and exit
	for {
		time.Sleep(30 * time.Second)
		if time.Since(lastSeen) > 30*time.Second {
			fmt.Println("Connection lost, exiting...")
			os.Exit(0)
		}
	}
}
