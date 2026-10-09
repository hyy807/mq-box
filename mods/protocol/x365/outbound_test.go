package x365

import (
	"net"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// TestSerializeAddrPort 锁定地址编码布局：port(BE) → atyp → address。
// 该布局是从参考实现（core.dll 反汇编还原）逐字段确认的，改动会直接导致
// 服务端拒绝，因此必须被测试保护。
func TestSerializeAddrPort(t *testing.T) {
	cases := []struct {
		name string
		dest M.Socksaddr
		want []byte
	}{
		{
			name: "ipv4",
			dest: M.ParseSocksaddr("1.2.3.4:443"),
			want: []byte{0x01, 0xbb, 0x01, 1, 2, 3, 4},
		},
		{
			name: "domain",
			dest: M.ParseSocksaddr("example.com:80"),
			want: append([]byte{0x00, 0x50, 0x02, 11}, []byte("example.com")...),
		},
		{
			name: "ipv6",
			dest: M.ParseSocksaddr("[2001:db8::1]:53"),
			want: append([]byte{0x00, 0x35, 0x03}, net.ParseIP("2001:db8::1").To16()...),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := serializeAddrPort(tc.dest)
			if len(got) != len(tc.want) {
				t.Fatalf("length mismatch: got %d want %d (%x)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("byte %d mismatch: got %x want %x", i, got, tc.want)
				}
			}
		})
	}
}

// TestParseUUIDKey UUID 的原始 16 字节直接作为 key16，不做哈希。
func TestParseUUIDKey(t *testing.T) {
	key, err := parseUUIDKey("fe586856-88b5-43e3-951b-e8ff0aa51c29")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0xfe, 0x58, 0x68, 0x56, 0x88, 0xb5, 0x43, 0xe3,
		0x95, 0x1b, 0xe8, 0xff, 0x0a, 0xa5, 0x1c, 0x29,
	}
	for i := range want {
		if key[i] != want[i] {
			t.Fatalf("byte %d: got %02x want %02x", i, key[i], want[i])
		}
	}
	if _, err = parseUUIDKey("not-a-uuid"); err == nil {
		t.Fatal("expected error for invalid uuid")
	}
}

// TestHandshakeFrameLayout 锁定握手帧头：X365 + 0x01 + command + key16。
func TestHandshakeFrameLayout(t *testing.T) {
	key, err := parseUUIDKey("fe586856-88b5-43e3-951b-e8ff0aa51c29")
	if err != nil {
		t.Fatal(err)
	}
	h := &Outbound{key: key}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 64)
		n, _ := server.Read(buffer)
		done <- buffer[:n]
	}()

	if err := h.writeHandshake(client, commandTCP, M.ParseSocksaddr("example.com:443")); err != nil {
		t.Fatal(err)
	}
	frame := <-done
	if string(frame[:4]) != "X365" {
		t.Fatalf("bad magic: %q", frame[:4])
	}
	if frame[4] != frameVersion {
		t.Fatalf("bad version: %x", frame[4])
	}
	if frame[5] != commandTCP {
		t.Fatalf("bad command: %x", frame[5])
	}
	for i := 0; i < 16; i++ {
		if frame[6+i] != key[i] {
			t.Fatalf("bad key byte %d: %02x != %02x", i, frame[6+i], key[i])
		}
	}
}
