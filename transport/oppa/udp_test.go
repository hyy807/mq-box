package oppa

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func testChannel() M.Socksaddr {
	return M.SocksaddrFrom(netip.MustParseAddr("0.0.0.0"), 0)
}

func TestUDPConnWriteFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := NewUDPConn(client, testChannel())
	destination := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.2"), 18084)
	go func() {
		_ = conn.WritePacketBytes([]byte("DYNAMIC_UDP_0"), destination)
	}()
	raw := make([]byte, 29)
	if _, err := io.ReadFull(server, raw); err != nil {
		t.Fatalf("read frame: %v", err)
	}
	expected := mustHex(t, "001b01000000000000017f00000246a444594e414d49435f5544505f30")
	if !bytes.Equal(raw, expected) {
		t.Fatalf("frame mismatch\n got %s\nwant %s", hex.EncodeToString(raw), hex.EncodeToString(expected))
	}
}

// Two frames coalesced into one write must be split by the reader.
func TestUDPConnCoalescedFrames(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := NewUDPConn(client, testChannel())
	first, _ := EncodeUDPFrame(testChannel(), M.SocksaddrFrom(netip.MustParseAddr("1.1.1.1"), 53), []byte("aaaa"))
	second, _ := EncodeUDPFrame(testChannel(), M.SocksaddrFrom(netip.MustParseAddr("2.2.2.2"), 53), []byte("bb"))
	go func() {
		_, _ = server.Write(append(first, second...))
	}()
	buffer := buf.NewSize(2048)
	destination, err := conn.ReadPacket(buffer)
	if err != nil {
		t.Fatalf("first packet: %v", err)
	}
	if destination.String() != "1.1.1.1:53" || string(buffer.Bytes()) != "aaaa" {
		t.Fatalf("first packet %s %q", destination, buffer.Bytes())
	}
	buffer.Reset()
	destination, err = conn.ReadPacket(buffer)
	if err != nil {
		t.Fatalf("second packet: %v", err)
	}
	if destination.String() != "2.2.2.2:53" || string(buffer.Bytes()) != "bb" {
		t.Fatalf("second packet %s %q", destination, buffer.Bytes())
	}
}

// A frame split across many writes must still decode, mirroring TLS record
// fragmentation and short reads.
func TestUDPConnFragmentedFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := NewUDPConn(client, testChannel())
	frame, _ := EncodeUDPFrame(testChannel(), M.SocksaddrFrom(netip.MustParseAddr("9.9.9.9"), 443), []byte("fragmented payload"))
	go func() {
		for index := 0; index < len(frame); index += 3 {
			end := index + 3
			if end > len(frame) {
				end = len(frame)
			}
			if _, err := server.Write(frame[index:end]); err != nil {
				return
			}
		}
	}()
	buffer := buf.NewSize(2048)
	destination, err := conn.ReadPacket(buffer)
	if err != nil {
		t.Fatalf("read fragmented packet: %v", err)
	}
	if destination.String() != "9.9.9.9:443" || string(buffer.Bytes()) != "fragmented payload" {
		t.Fatalf("packet %s %q", destination, buffer.Bytes())
	}
}

// Concurrent writers must never interleave frame bytes.
func TestUDPConnConcurrentWrites(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := NewUDPConn(client, testChannel())
	reader := NewUDPConn(server, testChannel())
	const count = 32
	type result struct {
		payload     []byte
		destination M.Socksaddr
		err         error
	}
	results := make(chan result, count)
	go func() {
		for index := 0; index < count; index++ {
			buffer := buf.NewSize(2048)
			destination, err := reader.ReadPacket(buffer)
			payload := append([]byte(nil), buffer.Bytes()...)
			buffer.Release()
			results <- result{payload, destination, err}
			if err != nil {
				return
			}
		}
	}()
	var waitGroup sync.WaitGroup
	for index := 0; index < count; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			_ = conn.WritePacketBytes(bytes.Repeat([]byte{byte(index)}, 64), M.SocksaddrFrom(netip.MustParseAddr("3.3.3.3"), uint16(1000+index)))
		}(index)
	}
	waitGroup.Wait()
	seen := make(map[int]bool)
	for index := 0; index < count; index++ {
		entry := <-results
		if entry.err != nil {
			t.Fatalf("frame %d: %v", index, entry.err)
		}
		if len(entry.payload) != 64 {
			t.Fatalf("frame %d payload length %d, interleaved: %q", index, len(entry.payload), entry.payload)
		}
		first := int(entry.payload[0])
		if bytes.Count(entry.payload, []byte{byte(first)}) != 64 {
			t.Fatalf("frame %d interleaved: %q", index, entry.payload)
		}
		if seen[first] {
			t.Fatalf("frame %d duplicated", first)
		}
		seen[first] = true
		if int(entry.destination.Port) != 1000+first {
			t.Fatalf("frame %d destination %s does not match payload", first, entry.destination)
		}
	}
}
