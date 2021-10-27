package api

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

/*
//go:embed ingest-enclave.css
var ingestEnclave []byte
*/

const (
	/// The length of the header1 field, in bytes
	HEADER_LEN = 16
	/// The length of the header2 field, in bytes
	HEADER2_LEN = 16
	/// The length of the SWDEFINED field, in bytes
	SWDEFINED_LEN = 4
	/// The length of the MODULUS field, in bytes
	PUBKEY_LEN = 384
	/// The length of the SIGNATURE field, in bytes
	SIGNATURE_LEN = PUBKEY_LEN
	/// The length of the ENCLAVEHASH field, in bytes
	MRENCLAVE_LEN = 32
	/// The length of the hash of the signer values, in bytes
	MRSIGNER_LEN = 32
	/// The length of the "Q1" signature verification value
	Q1_LEN = PUBKEY_LEN
	/// The length of the "Q2" signature verification value
	Q2_LEN = PUBKEY_LEN

	RESERVED1_LEN = 84
	RESERVED2_LEN = 20
	RESERVED3_LEN = 32
	RESERVED4_LEN = 12
)

var (
	ZEROV        [84]byte
	HEADER1      = [16]byte{0x06, 0x00, 0x00, 0x00, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
	HEADER2      = [16]byte{0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	VENDOR_INTEL = [4]byte{0x00, 0x00, 0x80, 0x86}
	VENDOR_OTHER [4]byte
)

type Signature struct {
	Header        [16]byte
	Vendor        [4]byte
	Date          [4]byte
	Header2       [16]byte
	Swdefined     [4]byte
	Reserved1     [RESERVED1_LEN]byte
	Modulus       [384]byte
	Exponent      [4]byte
	Signature     [384]byte
	Miscselect    [4]byte
	Miscmask      [4]byte
	Reserved2     [RESERVED2_LEN]byte
	Attributes    [16]byte
	Attributemask [16]byte
	Enclavehash   [32]byte
	Reserved3     [RESERVED3_LEN]byte
	Isvprodid     [2]byte
	Isvsvn        [2]byte
	Reserved4     [RESERVED4_LEN]byte
	Q1            [384]byte
	Q2            [384]byte
}

func parseSigFromBytes(buf []byte) *Signature {
	s := &Signature{}
	left := 0
	right := left + len(s.Header)
	copy(s.Header[:], buf[left:right])
	left = right
	right += len(s.Vendor)
	copy(s.Vendor[:], buf[left:right])
	left = right
	right += len(s.Date)
	copy(s.Date[:], buf[left:right])
	left = right
	right += len(s.Header2)
	copy(s.Header2[:], buf[left:right])
	left = right
	right += len(s.Swdefined)
	copy(s.Swdefined[:], buf[left:right])
	left = right
	right += len(s.Reserved1)
	copy(s.Reserved1[:], buf[left:right])
	left = right
	right += len(s.Modulus)
	copy(s.Modulus[:], buf[left:right])
	left = right
	right += len(s.Exponent)
	copy(s.Exponent[:], buf[left:right])
	left = right
	right += len(s.Signature)
	copy(s.Signature[:], buf[left:right])
	left = right
	right += len(s.Miscselect)
	copy(s.Miscselect[:], buf[left:right])
	left = right
	right += len(s.Miscmask)
	copy(s.Miscmask[:], buf[left:right])
	left = right
	right += len(s.Reserved2)
	copy(s.Reserved2[:], buf[left:right])
	left = right
	right += len(s.Attributes)
	copy(s.Attributes[:], buf[left:right])
	left = right
	right += len(s.Attributemask)
	copy(s.Attributemask[:], buf[left:right])
	left = right
	right += len(s.Enclavehash)
	copy(s.Enclavehash[:], buf[left:right])
	left = right
	right += len(s.Reserved3)
	copy(s.Reserved3[:], buf[left:right])
	left = right
	right += len(s.Isvprodid)
	copy(s.Isvprodid[:], buf[left:right])
	left = right
	right += len(s.Isvsvn)
	copy(s.Isvsvn[:], buf[left:right])
	left = right
	right += len(s.Reserved4)
	copy(s.Reserved4[:], buf[left:right])
	left = right
	right += len(s.Q1)
	copy(s.Q1[:], buf[left:right])
	left = right
	right += len(s.Q2)
	copy(s.Q2[:], buf[left:])
	return s
}

// TODO consensus-enclave.css will change once per quarter
func ParseSignature() (*Signature, error) {
	ingestEnclave, err := GetProductionData()
	if err != nil {
		return nil, err
	}
	s := &Signature{}
	if len(ingestEnclave) != s.Size() {
		return nil, fmt.Errorf("Signature size invalid: %d, source %d", s.Size(), len(ingestEnclave))
	}
	s = parseSigFromBytes(ingestEnclave)
	if bytes.Compare(s.Header[:], HEADER1[:]) != 0 {
		return nil, fmt.Errorf("Bad Header1")
	}
	if bytes.Compare(s.Vendor[:], VENDOR_INTEL[:]) != 0 && bytes.Compare(s.Vendor[:], VENDOR_OTHER[:]) != 0 {
		return nil, fmt.Errorf("Unknown Vendor")
	}
	if binary.LittleEndian.Uint32(s.Date[:]) < 0x2017_0120 {
		return nil, fmt.Errorf("Bad Date")
	}
	if bytes.Compare(s.Header2[:], HEADER2[:]) != 0 {
		return nil, fmt.Errorf("Bad Header2")
	}

	var reserved1 [RESERVED1_LEN]byte
	var reserved2 [RESERVED2_LEN]byte
	var reserved3 [RESERVED3_LEN]byte
	var reserved4 [RESERVED4_LEN]byte
	if bytes.Compare(s.Reserved1[:], reserved1[:]) != 0 {
		return nil, fmt.Errorf("Non Zero Reserved1")
	}
	if bytes.Compare(s.Reserved2[:], reserved2[:]) != 0 {
		return nil, fmt.Errorf("Non Zero Reserved2")
	}
	if bytes.Compare(s.Reserved3[:], reserved3[:]) != 0 {
		return nil, fmt.Errorf("Non Zero Reserved3")
	}
	if bytes.Compare(s.Reserved4[:], reserved4[:]) != 0 {
		return nil, fmt.Errorf("Non Zero Reserved4")
	}

	return s, nil
}

func (s *Signature) Size() int {
	return len(s.Header) +
		len(s.Vendor) +
		len(s.Date) +
		len(s.Header2) +
		len(s.Swdefined) +
		len(s.Reserved1) +
		len(s.Modulus) +
		len(s.Exponent) +
		len(s.Signature) +
		len(s.Miscselect) +
		len(s.Miscmask) +
		len(s.Reserved2) +
		len(s.Attributes) +
		len(s.Attributemask) +
		len(s.Enclavehash) +
		len(s.Reserved3) +
		len(s.Isvprodid) +
		len(s.Isvsvn) +
		len(s.Reserved4) +
		len(s.Q1) +
		len(s.Q2)
}

func (s *Signature) MrSigner() [sha256.Size]byte {
	return sha256.Sum256(s.Modulus[:])
}

func (s *Signature) ProductID() uint16 {
	return binary.LittleEndian.Uint16(s.Isvprodid[:])
}

func (s *Signature) Version() uint16 {
	return binary.LittleEndian.Uint16(s.Isvsvn[:])
}
func (s *Signature) MRENCLAVE() [32]byte {
	return s.Enclavehash
}

func GetProductionData() ([]byte, error) {
	resp, err := http.Get("https://enclave-distribution.prod.mobilecoin.com/production.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		Ingest struct {
			Sigstruct string `json:"sigstruct"`
		} `json:"ingest"`
	}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return nil, err
	}
	return GetConsensusEnclave(data.Ingest.Sigstruct)
}

func GetConsensusEnclave(path string) ([]byte, error) {
	resp, err := http.Get("https://enclave-distribution.prod.mobilecoin.com/" + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}
