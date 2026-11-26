//go:build !linux && !windows

package diag

import "errors"

var errPlatform = errors.New("this diagnostic requires Linux (including WSL2)")

func unsupported(layer int, name string) Result {
	return result(layer, name, Fail, "unsupported platform", nil, errPlatform)
}
func Physical(Options) Result  { return unsupported(1, "Physical") }
func Neighbors(Options) Result { return unsupported(2, "DataLink") }
func Network(Options) Result   { return unsupported(3, "Network") }
func localTransport(Options) Result { return unsupported(4, "Transport") }
func Sessions(Options) Result  { return unsupported(5, "Session") }
func PingOnly(Options) Result  { return unsupported(3, "Network") }
func TraceOnly(Options) Result { return unsupported(3, "Network") }
func Wireless(Options) Result  { return unsupported(1, "WiFi") }
