// vuln.go
package main

import (
	"fmt"
	"os"
	"os/exec"
)

func runCmd(input string) {
	exec.Command("sh", "-c", input).Run()
}

func readFile(name string) {
	// 路径穿越
	path := "/safe/dir/" + name
	os.ReadFile(path)
}

func main() {
	if len(os.Args) > 1 {
		runCmd(os.Args[1])
		readFile(os.Args[1])
		fmt.Println("done")
	}
}
