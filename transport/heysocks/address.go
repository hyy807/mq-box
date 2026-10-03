package heysocks

import (
	"encoding/binary"
	"io"
	"net/netip"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// Address types of the Heysocks destination address, byte aligned with
// serializesSocksAddr (RVA 0x6fe1e0) of the reference kernel:
//
//	IPv4   : 01 || IP[4]  big endian || port BE16
//	IPv6   : 04 || IP[16] big endian || port BE16
//	domain : 03 || len:u8 || domain    || port BE16
//
// There is no 05 01 00 negotiation header and no trailing length.
//
// Note: this is not the VMess address format (which uses 02 for domains and
// writes the port first); do not reuse a VMess serializer here.
const (
	AddressTypeIPv4   byte = 0x01
	AddressTypeDomain byte = 0x03
	AddressTypeIPv6   byte = 0x04
)

// WriteAddress appends the destination address to buffer.
func WriteAddress(buffer []byte, destination M.Socksaddr) ([]byte, error) {
	switch {
	case destination.IsIPv4():
		buffer = append(buffer, AddressTypeIPv4)
		address := destination.Addr.As4()
		buffer = append(buffer, address[:]...)
	case destination.IsIPv6():
		buffer = append(buffer, AddressTypeIPv6)
		address := destination.Addr.As16()
		buffer = append(buffer, address[:]...)
	case destination.IsFqdn():
		domain := destination.Fqdn
		if len(domain) == 0 || len(domain) > 255 {
			return nil, E.New("heysocks: invalid domain length ", len(domain))
		}
		buffer = append(buffer, AddressTypeDomain, byte(len(domain)))
		buffer = append(buffer, domain...)
	default:
		return nil, E.New("heysocks: unsupported destination address")
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], destination.Port)
	buffer = append(buffer, port[:]...)
	return buffer, nil
}

// AddressLength reports the encoded length for the destination.
func AddressLength(destination M.Socksaddr) (int, error) {
	switch {
	case destination.IsIPv4():
		return 7, nil
	case destination.IsIPv6():
		return 19, nil
	case destination.IsFqdn():
		length := len(destination.Fqdn)
		if length == 0 || length > 255 {
			return 0, E.New("heysocks: invalid domain length ", length)
		}
		return 1 + 1 + length + 2, nil
	default:
		return 0, E.New("heysocks: unsupported destination address")
	}
}

// ReadAddress decodes a destination address, used by the UDP reader and by
// tests that replay captured traffic.
func ReadAddress(reader io.Reader) (M.Socksaddr, error) {
	var addressType [1]byte
	if _, err := io.ReadFull(reader, addressType[:]); err != nil {
		return M.Socksaddr{}, E.Cause(err, "heysocks: read address type")
	}
	switch addressType[0] {
	case AddressTypeIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return M.Socksaddr{}, E.Cause(err, "heysocks: read IPv4 address")
		}
		return finishAddress(reader, M.Socksaddr{Addr: netip.AddrFrom4(raw)})
	case AddressTypeIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return M.Socksaddr{}, E.Cause(err, "heysocks: read IPv6 address")
		}
		return finishAddress(reader, M.Socksaddr{Addr: netip.AddrFrom16(raw)})
	case AddressTypeDomain:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return M.Socksaddr{}, E.Cause(err, "heysocks: read domain length")
		}
		if length[0] == 0 {
			return M.Socksaddr{}, E.New("heysocks: empty domain")
		}
		domain := make([]byte, length[0])
		if _, err := io.ReadFull(reader, domain); err != nil {
			return M.Socksaddr{}, E.Cause(err, "heysocks: read domain")
		}
		var port [2]byte
		if _, err := io.ReadFull(reader, port[:]); err != nil {
			return M.Socksaddr{}, E.Cause(err, "heysocks: read port")
		}
		return M.Socksaddr{Fqdn: strings.ToLower(string(domain)), Port: binary.BigEndian.Uint16(port[:])}, nil
	default:
		return M.Socksaddr{}, E.New("heysocks: unknown address type ", addressType[0])
	}
}

func finishAddress(reader io.Reader, address M.Socksaddr) (M.Socksaddr, error) {
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return M.Socksaddr{}, E.Cause(err, "heysocks: read port")
	}
	address.Port = binary.BigEndian.Uint16(port[:])
	return address, nil
}
