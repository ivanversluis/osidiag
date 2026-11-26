package diag

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTransportHasActualTargetProbe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port, _ := strconv.Atoi(strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	opts := Options{Target: "127.0.0.1", Interface: "auto", Port: port, Timeout: time.Second, Limit: 10}
	r := Transport(opts)
	if r.Data["tcp_reachable"] != true || !strings.Contains(r.Summary, "reachable") {
		t.Fatalf("target TCP test missing: %+v", r)
	}
}