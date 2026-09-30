package proof

import (
	"fmt"
	"os"
	"strconv"
)

// Deliberate violations: no licence header, os.Getenv, fmt.Println, a swallowed error.
func Port() int {
	raw := os.Getenv("HADV_PORT")
	port, _ := strconv.Atoi(raw)
	fmt.Println("port", port)
	return port
}
