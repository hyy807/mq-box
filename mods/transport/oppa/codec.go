package oppa

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// Wire format of the Oppa / sslhop application layer, as implemented by the
// reference clients (Android libleaf.so, Windows leaf.exe):
//
//	TCP: AUTH_RAW32 || 0x01 || SOCKS_ADDR(destination)
//	UDP channel: AUTH_RAW32 || 0x02
//	UDP frame: BODY_LEN_BE16 || SOCKS_ADDR(channel) || SOCKS_ADDR(destination) || payload
//
// AUTH_RAW32 is the raw UTF-8 password, exactly 32 bytes, no hashing and no
// length/version prefix.

const (
	CommandTCP byte = 0x01
	CommandUDP byte = 0x02
)

const (
	AddressTypeIPv4 byte = 0x01
	AddressTypeFqdn byte = 0x03
	AddressTypeIPv6 byte = 0x04
)

const (
	// PasswordSize is the fixed password length required by the reference
	// Windows client: 32 bytes after UTF-8 encoding, not 32 characters.
	PasswordSize = 32
	// MaxUDPBody is the largest body accepted by the reference Android
	// receiver. Larger frames are rejected instead of truncated.
	MaxUDPBody = 2048
	// MaxAddressLength is 1 + 255 + 2 (fqdn) and 1 + 16 + 2 (ip6).
	MaxAddressLength = 258
)

var (
	ErrInvalidPassword = E.New("oppa: password must be exactly 32 bytes (UTF-8)")
	ErrInvalidAddress  = E.New("oppa: invalid destination address")
	ErrFrameTooLarge   = E.New("oppa: UDP frame body exceeds ", MaxUDPBody, " bytes")
)

// ValidatePassword enforces the reference client's fixed-length check.
func ValidatePassword(password string) error {
	if len(password) != PasswordSize {
		return E.Cause(ErrInvalidPassword, "got ", len(password), " bytes")
	}
	return nil
}

// AddressLength returns the encoded length of a SOCKS_ADDR:
// 7 for IPv4, 19 for IPv6, 1 + n + 4 for a domain.
func AddressLength(destination M.Socksaddr) (int, error) {
	switch {
	case destination.IsIPv4():
		return 1 + 4 + 2, nil
	case destination.IsIPv6():
		return 1 + 16 + 2, nil
	case destination.IsFqdn():
		length := len(destination.Fqdn)
		if length == 0 || length > 255 {
			return 0, E.Cause(ErrInvalidAddress, "invalid domain length ", length)
		}
		return 1 + 1 + length + 2, nil
	default:
		return 0, E.Cause(ErrInvalidAddress, "unsupported address family")
	}
}

// WriteAddress encodes one SOCKS_ADDR.
func WriteAddress(writer io.Writer, destination M.Socksaddr) error {
	switch {
	case destination.IsIPv4():
		if _, err := writer.Write([]byte{AddressTypeIPv4}); err != nil {
			return err
		}
		address := destination.Addr.As4()
		if _, err := writer.Write(address[:]); err != nil {
			return err
		}
	case destination.IsIPv6():
		if _, err := writer.Write([]byte{AddressTypeIPv6}); err != nil {
			return err
		}
		address := destination.Addr.As16()
		if _, err := writer.Write(address[:]); err != nil {
			return err
		}
	case destination.IsFqdn():
		length := len(destination.Fqdn)
		if length == 0 || length > 255 {
			return E.Cause(ErrInvalidAddress, "invalid domain length ", length)
		}
		if _, err := writer.Write([]byte{AddressTypeFqdn, byte(length)}); err != nil {
			return err
		}
		if _, err := writer.Write([]byte(destination.Fqdn)); err != nil {
			return err
		}
	default:
		return E.Cause(ErrInvalidAddress, "unsupported address family")
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], destination.Port)
	_, err := writer.Write(port[:])
	return err
}

// AppendAddress appends an encoded SOCKS_ADDR to a byte slice.
func AppendAddress(buffer []byte, destination M.Socksaddr) ([]byte, error) {
	writer := bytes.NewBuffer(buffer)
	if err := WriteAddress(writer, destination); err != nil {
		return nil, err
	}
	return writer.Bytes(), nil
}

// ReadAddress decodes one SOCKS_ADDR from reader.
func ReadAddress(reader io.Reader) (M.Socksaddr, error) {
	var addressType [1]byte
	if _, err := io.ReadFull(reader, addressType[:]); err != nil {
		return M.Socksaddr{}, E.Cause(err, "read address type")
	}
	var address netip.Addr
	switch addressType[0] {
	case AddressTypeIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return M.Socksaddr{}, E.Cause(err, "read IPv4 address")
		}
		address = netip.AddrFrom4(raw)
	case AddressTypeIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return M.Socksaddr{}, E.Cause(err, "read IPv6 address")
		}
		address = netip.AddrFrom16(raw)
	case AddressTypeFqdn:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return M.Socksaddr{}, E.Cause(err, "read domain length")
		}
		if length[0] == 0 {
			return M.Socksaddr{}, E.Cause(ErrInvalidAddress, "empty domain")
		}
		raw := make([]byte, length[0])
		if _, err := io.ReadFull(reader, raw); err != nil {
			return M.Socksaddr{}, E.Cause(err, "read domain")
		}
		rawPort, err := readPort(reader)
		if err != nil {
			return M.Socksaddr{}, err
		}
		return M.Socksaddr{Fqdn: string(raw), Port: rawPort}, nil
	default:
		return M.Socksaddr{}, E.Cause(ErrInvalidAddress, "unknown address type ", addressType[0])
	}
	rawPort, err := readPort(reader)
	if err != nil {
		return M.Socksaddr{}, err
	}
	return M.Socksaddr{Addr: address, Port: rawPort}, nil
}

func readPort(reader io.Reader) (uint16, error) {
	var raw [2]byte
	if _, err := io.ReadFull(reader, raw[:]); err != nil {
		return 0, E.Cause(err, "read port")
	}
	return binary.BigEndian.Uint16(raw[:]), nil
}

// WriteRequest writes the stream header: AUTH_RAW32 || command || SOCKS_ADDR.
func WriteRequest(writer io.Writer, password string, command byte, destination M.Socksaddr) error {
	buffer := bytes.NewBuffer(make([]byte, 0, PasswordSize+1+MaxAddressLength))
	buffer.WriteString(password)
	buffer.WriteByte(command)
	if err := WriteAddress(buffer, destination); err != nil {
		return err
	}
	_, err := writer.Write(buffer.Bytes())
	return err
}

// WriteChannelRequest writes the UDP channel header: AUTH_RAW32 || 0x02.
func WriteChannelRequest(writer io.Writer, password string) error {
	_, err := writer.Write([]byte(password + string([]byte{CommandUDP})))
	return err
}

// EncodeUDPFrame encodes one UDP data frame.
func EncodeUDPFrame(channel M.Socksaddr, destination M.Socksaddr, payload []byte) ([]byte, error) {
	channelLength, err := AddressLength(channel)
	if err != nil {
		return nil, E.Cause(err, "channel address")
	}
	destinationLength, err := AddressLength(destination)
	if err != nil {
		return nil, E.Cause(err, "destination address")
	}
	bodyLength := channelLength + destinationLength + len(payload)
	if bodyLength > MaxUDPBody {
		return nil, E.Cause(ErrFrameTooLarge, "got ", bodyLength)
	}
	frame := make([]byte, 0, 2+bodyLength)
	frame = binary.BigEndian.AppendUint16(frame, uint16(bodyLength))
	frame, err = AppendAddress(frame, channel)
	if err != nil {
		return nil, err
	}
	frame, err = AppendAddress(frame, destination)
	if err != nil {
		return nil, err
	}
	frame = append(frame, payload...)
	return frame, nil
}

// DecodeUDPFrame decodes one UDP data frame: body length, channel address,
// destination address and payload.
func DecodeUDPFrame(reader io.Reader) (channel M.Socksaddr, destination M.Socksaddr, payload []byte, err error) {
	var rawLength [2]byte
	if _, err = io.ReadFull(reader, rawLength[:]); err != nil {
		return M.Socksaddr{}, M.Socksaddr{}, nil, E.Cause(err, "read frame length")
	}
	bodyLength := int(binary.BigEndian.Uint16(rawLength[:]))
	if bodyLength == 0 {
		return M.Socksaddr{}, M.Socksaddr{}, nil, E.Cause(ErrInvalidAddress, "empty frame body")
	}
	if bodyLength > MaxUDPBody {
		return M.Socksaddr{}, M.Socksaddr{}, nil, E.Cause(ErrFrameTooLarge, "got ", bodyLength)
	}
	body := make([]byte, bodyLength)
	if _, err = io.ReadFull(reader, body); err != nil {
		return M.Socksaddr{}, M.Socksaddr{}, nil, E.Cause(err, "read frame body")
	}
	bodyReader := bytes.NewReader(body)
	channel, err = ReadAddress(bodyReader)
	if err != nil {
		return M.Socksaddr{}, M.Socksaddr{}, nil, E.Cause(err, "decode channel address")
	}
	destination, err = ReadAddress(bodyReader)
	if err != nil {
		return M.Socksaddr{}, M.Socksaddr{}, nil, E.Cause(err, "decode destination address")
	}
	payload = body[bodyLength-bodyReader.Len():]
	return channel, destination, payload, nil
}
