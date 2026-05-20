package netmon

import "testing"

// TestPort checks conversion of a network-byte-order port DWORD to host order.
func TestPort(t *testing.T) {
	if got := port(0x5000); got != 80 { // 80 = 0x0050 network order
		t.Errorf("port(0x5000) = %d, want 80", got)
	}
	if got := port(0xBB01); got != 443 { // 443 = 0x01BB network order
		t.Errorf("port(0xBB01) = %d, want 443", got)
	}
}

// TestIPv4 checks formatting of a network-byte-order IPv4 DWORD.
func TestIPv4(t *testing.T) {
	if got := ipv4(0x0100007F); got != "127.0.0.1" { // 127.0.0.1
		t.Errorf("ipv4 = %q, want 127.0.0.1", got)
	}
	if got := ipv4(0x0101A8C0); got != "192.168.1.1" { // 192.168.1.1
		t.Errorf("ipv4 = %q, want 192.168.1.1", got)
	}
}

func TestTCPState(t *testing.T) {
	cases := map[uint32]string{2: "LISTEN", 5: "ESTABLISHED", 11: "TIME-WAIT"}
	for code, want := range cases {
		if got := tcpState(code); got != want {
			t.Errorf("tcpState(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestServiceName(t *testing.T) {
	cases := map[uint16]string{443: "HTTPS", 80: "HTTP", 53: "DNS", 3389: "RDP", 63123: ""}
	for portNum, want := range cases {
		if got := serviceName(portNum); got != want {
			t.Errorf("serviceName(%d) = %q, want %q", portNum, got, want)
		}
	}
}
