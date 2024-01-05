/*
   ____________   ___    ____     ___
  / __/ ___/ _ | / _ \  /  _/__  / _/__
 _\ \/ /__/ __ |/ ___/ _/ // _ \/ _/ _ \
/___/\___/_/ |_/_/    /___/_//_/_/ \___/

SCAP Info
(c) fG! 2024 - reverser@put.as - https://reverse.put.as

A small utility to extract version information from Apple EFI SCAP files.

*/

package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/gdbinit/scap_info/pkg/guid"
	"github.com/schollz/progressbar/v3"
	"io/ioutil"
	"math/big"
	"os"
	"regexp"
	"strings"
	"path/filepath"
)

// version info to be modified runtime by -X flag
var (
	Version = "1.0"
	Build   = "0"
	Time    = "none"
	GitHash = "none"
	verbose bool
)

const (
	EFI_FVH_SIGNATURE                 = 0x4856465F
	CAPSULE_GUID                      = "3B6686BD-0D76-4030-B70E-B5519E2FC5A0"
	FFS1_GUID                         = "7A9354D9-0468-444A-81CE-0BF617D890DF"
	EFI_CERT_TYPE_RSA2048_SHA256_GUID = "A7717414-C616-4977-9420-844712A735BF"
	EFIBIOSID_GUID                    = "C3E36D09-8294-4B97-A857-D5288FE33E28"
	AppleRomInformation_GUID          = "B535ABF6-967D-43F2-B494-A1EB8E21A28E"
	ApplePubKey                       = "-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw+dIytnNOEMp4Q4lqR5D\n4adi/1Ka3leMk1vd+bE/IXnUhV5vyJ6eKcoSUX0X36Htzgvr8Op7Rh/+YdlOK99y\nwZb4ms01NrZEBkAU2uJaFdtrsIUuy9EgkWMY0czeo8hMku10P8F20LrKkg0/zzFY\nr/cx+IzgYjGCqO1n5lBRX3V0WQnwfUFfVfwVo1ZU0RjFWkYtN6Os2ghhLz8/ZXF2\nHvzLzCma7pmzpP1iEsz/9e83osM06HEZH34cMZYOAQpU6G+j9i5taQXhzVdzJBCj\n6wxrTe/avp9ZvxYYdYx1HNVs74UdHA6qHFWON6wQjakImGPSDi5+S/R17Gb+az79\nzwIDAQAB\n-----END RSA PUBLIC KEY-----"
	ApplePubKeySHA256                 = "bcc5659cd17be6b85bb9dc971c0370aa7e47e159f86ca1cdbe2c5b948e68a45e"
)

type EFI_FV_BLOCK_MAP_ENTRY struct {
	NumBlocks uint32
	Length    uint32
}

type FirmwareVolumeFixedHeader struct {
	Zero            [16]uint8
	FileSystemGUID  guid.GUID
	Length          uint64
	Signature       uint32
	Attributes      uint32 // UEFI PI spec volume 3.2.1 EFI_FIRMWARE_VOLUME_HEADER
	HeaderLen       uint16
	Checksum        uint16
	ExtHeaderOffset uint16
	Reserved        uint8
	Revision        uint8
	FvBlockMap      [2]EFI_FV_BLOCK_MAP_ENTRY
}

type EFICapsuleHeader struct {
	CapsuleGuid guid.GUID
	HeaderSize  uint32
	Flags       uint32
	ImageSize   uint32
}

// IntegrityCheck holds the two 8 bit checksums for the file header and body separately.
type IntegrityCheck struct {
	Header uint8
	File   uint8
}

// FileHeader represents an EFI File header.
type FileHeader struct {
	GUID       guid.GUID // This is the GUID of the file.
	Checksum   IntegrityCheck
	Type       FVFileType
	Attributes uint8
	Size       [3]uint8
	State      uint8
}

// SectionHeader represents an EFI_COMMON_SECTION_HEADER as specified in
// UEFI PI Spec 3.2.4 Firmware File Section
type SectionHeader struct {
	Size [3]uint8
	Type uint8
}

// FVFileType represents the different types possible in an EFI file.
type FVFileType uint8

// UEFI FV File types.
const (
	FVFileTypeAll FVFileType = iota
	FVFileTypeRaw
	FVFileTypeFreeForm
	FVFileTypeSECCore
	FVFileTypePEICore
	FVFileTypeDXECore
	FVFileTypePEIM
	FVFileTypeDriver
	FVFileTypeCombinedPEIMDriver
	FVFileTypeApplication
	FVFileTypeSMM
	FVFileTypeVolumeImage
	FVFileTypeCombinedSMMDXE
	FVFileTypeSMMCore
	FVFileTypeSMMStandalone
	FVFileTypeSMMCoreStandalone
	FVFileTypeOEMMin   FVFileType = 0xC0
	FVFileTypeOEMMax   FVFileType = 0xDF
	FVFileTypeDebugMin FVFileType = 0xE0
	FVFileTypeDebugMax FVFileType = 0xEF
	FVFileTypePad      FVFileType = 0xF0
	FVFileTypeFFSMin   FVFileType = 0xF0
	FVFileTypeFFSMax   FVFileType = 0xFF
)

type EFI_CERT_BLOCK_RSA_2048_SHA256 struct {
	HashType  guid.GUID
	PublicKey [256]uint8
	Signature [256]uint8
}

type AppleRomInfo struct {
	Model      string `json:"model,omitempty"`      // Model or BIOS ID
	EFIVersion string `json:"efiversion,omitempty"` // EFI Version - not present on older
	Date       string `json:"date,omitempty"`       // Date
	Revision   string `json:"revision,omitempty"`   // Revision
	ROM        string `json:"romversion,omitempty"` // ROM Version
	Compiler   string `json:"compiler,omitempty"`   // Compiler - not present on older
}

type EFIBIOSId struct {
	Version string `json:"version"`
}

type OutputInfo struct {
	AppleROM AppleRomInfo `json:"applerom,omitempty"`
	EFI      EFIBIOSId    `json:"efi"`
	SHA256   string       `json:"sha256"`
	Size     int          `json:"size"`
}

// Debug print if verbose flag is set
func Debugf(format string, args ...interface{}) {
	if verbose {
		fmt.Printf(format, args...)
	}
}

// Checksum16 does a 16 bit checksum of the byte slice passed in.
func Checksum16(buf []byte) (uint16, error) {
	r := bytes.NewReader(buf)
	buflen := len(buf)
	if buflen%2 != 0 {
		return 0, fmt.Errorf("byte slice does not have even length, not able to do 16 bit checksum. Length was %v",
			buflen)
	}
	var temp, sum uint16
	for i := 0; i < buflen; i += 2 {
		if err := binary.Read(r, binary.LittleEndian, &temp); err != nil {
			return 0, err
		}
		sum += temp
	}
	return 0 - sum, nil
}

// Read3Size reads a 3-byte size and returns it as a uint64
func Read3Size(size [3]uint8) uint64 {
	return uint64(size[2])<<16 |
		uint64(size[1])<<8 | uint64(size[0])
}

func reverseByteOrder(data []byte) {
	length := len(data)
	for i := 0; i < length/2; i++ {
		data[i], data[length-i-1] = data[length-i-1], data[i]
	}
}

// Align aligns an address
func Align(val uint64, base uint64) uint64 {
	return (val + base - 1) & ^(base - 1)
}

// Align8 aligns an address to 8 bytes
func Align8(val uint64) uint64 {
	return Align(val, 8)
}

func ValidateFirmwareVolumeChecksum(buf []byte) (bool, error) {
	fvh, err := GetFirmwareVolumeHeader(buf)
	if err != nil {
		return false, err
	}
	// store the checksum since we will overwrite it
	srcChecksum := fvh.Checksum

	// make a copy to a structure so that we can reset the checksum and compute it again
	// XXX: is there a better way to do this in Go? Royal pain all this copy back and forth
	//      to just access the field instead of hardcoding an offset

	// reset the checksum
	fvh.Checksum = 0
	// now copy the modified structure copy back to a bytes buffer that we can checksum
	var copyBuf bytes.Buffer
	err = binary.Write(&copyBuf, binary.LittleEndian, &fvh)
	if err != nil {
		return false, err
	}
	dataToChecksum := copyBuf.Bytes()
	// fmt.Println("Firmare Volume Header Data to checksum", dataToChecksum, len(dataToChecksum))
	// validate the checksum
	headerCRC, err := Checksum16(dataToChecksum)
	if err != nil {
		return false, err
	}
	if headerCRC != srcChecksum {
		return false, fmt.Errorf("checksum doesn't match")
	}
	Debugf("Computed Header CRC: 0x%x\n", headerCRC)
	Debugf("Header Checksum: 0x%x\n", srcChecksum)
	return true, nil
}

func ValidateSignature(buf []byte) (bool, error) {
	header, err := GetEFICapsuleHeader(buf)
	if err != nil {
		return false, err
	}
	fvh, err := GetFirmwareVolumeHeader(buf)
	if err != nil {
		return false, err
	}
	rsaHeader := EFI_CERT_BLOCK_RSA_2048_SHA256{}
	rsaData := buf[fvh.Length+uint64(header.HeaderSize):]
	reader := bytes.NewReader(rsaData)
	err = binary.Read(reader, binary.LittleEndian, &rsaHeader)
	// fmt.Println(rsaHeader.HashType)
	if rsaHeader.HashType.String() != EFI_CERT_TYPE_RSA2048_SHA256_GUID {
		return false, fmt.Errorf("hash type not supported")
	}

	// we need to reverse the original data byte order
	reverseByteOrder(rsaHeader.PublicKey[:])
	reverseByteOrder(rsaHeader.Signature[:])

	pubKeyHash := sha256.Sum256(rsaHeader.PublicKey[:])
	if hex.EncodeToString(pubKeyHash[:]) != ApplePubKeySHA256 {
		return false, fmt.Errorf("Unexpected public key. Tampered or damaged file?")
	}

	// fmt.Println(len(rsaHeader.PublicKey), rsaHeader.PublicKey)
	// fmt.Println(len(rsaHeader.Signature), rsaHeader.Signature)

	modulus := new(big.Int).SetBytes(rsaHeader.PublicKey[:])
	exponentStr := "65537"
	exponent, success := new(big.Int).SetString(exponentStr, 10)
	if !success {
		return false, fmt.Errorf("Invalid exponent")
	}

	// Create the RSA public key
	publicKey := rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}
	// Encode the public key to PEM format
	pubASN1, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return false, err
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	// Print or use the PEM-encoded public key
	Debugf("Public key (PEM format):\n")
	Debugf("%s\n", string(pubPEM))

	// Hash the data and verify the signature
	// the whole firmware volume is what is signed
	hash := sha256.Sum256(buf[header.HeaderSize : uint64(header.HeaderSize)+fvh.Length])
	Debugf("[+] Firmware volume SHA256: %s\n", hex.EncodeToString(hash[:]))
	// verify the signature
	err = rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, hash[:], rsaHeader.Signature[:])
	if err != nil {
		return false, err
	}
	Debugf("[+] Signature is valid!\n")
	return true, nil
}

// returns a EFICapsuleHeader structure
func GetEFICapsuleHeader(buf []byte) (EFICapsuleHeader, error) {
	reader := bytes.NewReader(buf)
	header := EFICapsuleHeader{}
	err := binary.Read(reader, binary.LittleEndian, &header)
	if err != nil {
		return EFICapsuleHeader{}, err
	}
	if header.CapsuleGuid.String() != CAPSULE_GUID {
		return EFICapsuleHeader{}, fmt.Errorf("target file is not an EFI Capsule")
	}
	return header, nil
}

func GetFirmwareVolumeHeader(buf []byte) (FirmwareVolumeFixedHeader, error) {
	capsuleHeader, err := GetEFICapsuleHeader(buf)
	if err != nil {
		return FirmwareVolumeFixedHeader{}, err
	}
	/* the volumes start after the header */
	fvData := buf[capsuleHeader.HeaderSize:]
	fvh := FirmwareVolumeFixedHeader{}
	reader := bytes.NewReader(fvData)
	err = binary.Read(reader, binary.LittleEndian, &fvh)
	if err != nil {
		return FirmwareVolumeFixedHeader{}, err
	}
	if fvh.Signature != EFI_FVH_SIGNATURE {
		return FirmwareVolumeFixedHeader{}, fmt.Errorf("not a firmware volume")
	}

	return fvh, nil
}

func GetSectionData(buf []byte, myguid string) ([]byte, error) {
	header, err := GetEFICapsuleHeader(buf)
	if err != nil {
		return []byte{}, err
	}

	fvh, err := GetFirmwareVolumeHeader(buf)
	if err != nil {
		return []byte{}, err
	}

	fvBodyLen := fvh.Length - uint64(fvh.HeaderLen)
	pos := uint64(fvh.HeaderLen)
	fvData := buf[header.HeaderSize:]
	for pos < fvBodyLen {
		filePtr := fvData[pos:]
		reader := bytes.NewReader(filePtr)
		fh := FileHeader{}
		err = binary.Read(reader, binary.LittleEndian, &fh)
		if err != nil {
			return []byte{}, err
		}
		// the ones that we are interested in - we expect it to be FreeForm type
		if fh.GUID.String() == myguid && fh.Type == FVFileTypeFreeForm {
			sectionData := filePtr[binary.Size(FileHeader{}):]
			return sectionData, nil
		}
		// move to next item - we need to take care of alignment
		pos += Align8(Read3Size(fh.Size))
		// XXX: we are not detecting the last one and loop exiting via size check
	}
	return []byte{}, fmt.Errorf("guid not found")
}

func GetEFIBiosID(buf []byte) (EFIBIOSId, error) {
	sectionData, err := GetSectionData(buf, EFIBIOSID_GUID)
	if err != nil {
		fmt.Printf("[-] ERROR: Failed to retrieve EFI Bios ID section: %v\n", err)
		return EFIBIOSId{}, err
	}

	reader := bytes.NewReader(sectionData)
	sectionHeader := SectionHeader{}
	sectionHeaderSize := binary.Size(SectionHeader{})
	err = binary.Read(reader, binary.LittleEndian, &sectionHeader)
	if err != nil {
		fmt.Println("[-] ERROR: Failed to read section header.")
		// XXX: what do we do?
	}
	// fmt.Println(Read3Size(sectionHeader.Size))
	// the raw data is after the section header
	rawData := sectionData[sectionHeaderSize:Read3Size(sectionHeader.Size)]
	// fmt.Println(string(rawData))
	inputText := string(rawData)
	// Find the indices of "$IBIOSI$" and "Copyright"
	startIndex := strings.Index(inputText, "$IBIOSI$")
	endIndex := strings.Index(inputText, "Copyright")
	if startIndex != -1 && endIndex != -1 {
		// Extract the text between "$IBIOSI$" and "Copyright"
		finalText := inputText[startIndex+len("$IBIOSI$") : endIndex]
		// TrimSpace doesn't work so we go the hard way
		finalText = strings.TrimLeft(finalText, "\x20\x00")
		// the string is utf-16 and all the bytes will show up in the JSON
		// so we remove them the dumb way
		// XXX: this is ugly :P
		finalTextBytes := []byte(finalText)
		cleanText := make([]byte, 0)
		for i := 0; i < len(finalTextBytes); i++ {
			if finalTextBytes[i] != 0 {
				cleanText = append(cleanText, finalTextBytes[i])
			}
		}
		ret := EFIBIOSId{
			Version: string(cleanText),
		}
		return ret, nil
	} else {
		return EFIBIOSId{}, fmt.Errorf("bios id not found")
	}
}

func GetAppleRomInfo(buf []byte) (AppleRomInfo, error) {
	sectionData, err := GetSectionData(buf, AppleRomInformation_GUID)
	if err != nil {
		// fmt.Printf("[-] ERROR: Failed to retrieve Apple Rom Info section: %v\n", err)
		return AppleRomInfo{}, err
	}

	reader := bytes.NewReader(sectionData)
	sectionHeader := SectionHeader{}
	sectionHeaderSize := binary.Size(SectionHeader{})
	err = binary.Read(reader, binary.LittleEndian, &sectionHeader)
	if err != nil {
		// fmt.Println("[-] ERROR: Failed to read section header.")
		return AppleRomInfo{}, err
		// XXX: what do we do?
	}
	// fmt.Println(Read3Size(sectionHeader.Size))
	// the raw data is after the section header
	rawData := sectionData[sectionHeaderSize:Read3Size(sectionHeader.Size)]
	// fmt.Println(string(rawData))
	inputText := string(rawData)
	// ChatGPT territory here... why bother with regexps ever again :-)
	// Split the input text into lines
	lines := strings.Split(inputText, "\n")
	// Define the regular expression pattern to match pairs of fields
	pattern := `\s+([A-Za-z\s]+):\s+([^\n]+)`
	// Compile the regular expression pattern
	re := regexp.MustCompile(pattern)
	// Create a map to store extracted fields and their values
	fields := make(map[string]string)
	// Process lines skipping the first line
	startIndex := 1 // Skip the first line ("Apple ROM Version")
	for i := startIndex; i < len(lines); i++ {
		line := lines[i]
		// Find all matches in the current line
		matches := re.FindStringSubmatch(line)
		// Extract and store pairs of fields and values
		if len(matches) == 3 {
			field := strings.TrimSpace(matches[1])
			value := strings.TrimSpace(matches[2])
			fields[field] = value
		}
	}
	// Display the extracted fields and values
	// We want "BIOS ID" and "ROM Version" for file naming
	// for field, value := range fields {
	// 	fmt.Printf("%s -> %s\n", field, value)
	// }
	ret := AppleRomInfo{
		Model:      fields["Model"],
		EFIVersion: fields["EFI Version"],
		Date:       fields["Date"],
		Revision:   fields["Revision"],
		ROM:        fields["ROM Version"],
		Compiler:   fields["Compiler"],
	}
	// older versions use BIOS ID instead of Model
	if val, ok := fields["BIOS ID"]; ok {
		ret.Model = val
	}

	return ret, nil
}

func AnalyseFile(input_file string) (OutputInfo, error) {
	f, err := os.Open(input_file)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	input_buf, err := ioutil.ReadAll(f)

	header, err := GetEFICapsuleHeader(input_buf)
	if err != nil {
		return OutputInfo{}, err
	}

	Debugf("------ Capsule Header ------\n")
	Debugf("GUID: %s\n", header.CapsuleGuid)
	Debugf("Full Size: %d\n", header.ImageSize)
	Debugf("Header Size: %d\n", header.HeaderSize)
	Debugf("Flags: %d\n", header.Flags)
	Debugf("Capsule Size: %d\n", header.ImageSize-header.HeaderSize)

	/* the volumes start after the header */
	fvh, err := GetFirmwareVolumeHeader(input_buf)
	if err != nil {
		fmt.Printf("[-] ERROR: failed to read: %v\n", err)
		return OutputInfo{}, err
	}

	Debugf("------ Firmware Volume Header ------\n")
	// Debugf("%#v\n", fvh)
	Debugf("Zero: %v\n", fvh.Zero)
	Debugf("GUID: %s\n", fvh.FileSystemGUID)
	Debugf("Length: %d\n", fvh.Length)
	Debugf("Signature: %x\n", fvh.Signature)
	Debugf("Attributes: %x\n", fvh.Attributes)
	Debugf("Header len: %d\n", fvh.HeaderLen)
	Debugf("Checksum: %x\n", fvh.Checksum)
	Debugf("Extended offset: %d\n", fvh.ExtHeaderOffset)
	Debugf("Reserved: %x\n", fvh.Reserved)
	Debugf("Revision: %d\n", fvh.Revision)
	Debugf("----------------------------------\n")

	valid, err := ValidateFirmwareVolumeChecksum(input_buf)
	if err != nil {
		fmt.Printf("[-] ERROR: Firmware Volume checksum failed: %v", err)
		return OutputInfo{}, err
	}
	valid, err = ValidateSignature(input_buf)
	if err != nil {
		fmt.Printf("[-] ERROR: Signature verification failed: %v", err)
		return OutputInfo{}, err
	}
	if !valid {
		fmt.Println("[-] ERROR: Invalid signature detected.")
		return OutputInfo{}, err
	}
	// now we can proceed parsing the firmware volume contents
	// we are interested in two GUIDs: EFIBIOSID_GUID and AppleRomInformation_GUID
	// the first one appears to always exist while the second not
	//
	// layout is:
	// SCAP Header (0x50 bytes)
	// Firmware Volume Header (0x48 bytes)
	// Followed by File Header
	// And then Section Headers and data

	biosid, err := GetEFIBiosID(input_buf)
	rominfo, err := GetAppleRomInfo(input_buf)

	scapHash := sha256.Sum256(input_buf)
	// fmt.Println("[+] Target hash:", hex.EncodeToString(scapHash[:]))

	output := OutputInfo{
		AppleROM: rominfo,
		EFI:      biosid,
		SHA256:   hex.EncodeToString(scapHash[:]),
		Size:     len(input_buf),
	}

	return output, nil
}

func AnalyseFolder(input_folder string) ([]OutputInfo, error) {
    var err error
    output := make([]OutputInfo, 0)
    // who doesn't love a spinner!
    bar := progressbar.Default(-1, "processing")

    err = filepath.Walk(input_folder, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil
        }
        if info.Mode().IsRegular() {
			newentry, err2 := AnalyseFile(path)
			if err2 == nil {
				output = append(output, newentry)	
			}
			bar.Add(1)
        }
        return nil
    })
	if err != nil {
		fmt.Printf("[-] Error: walking through target folder: %s\n", err.Error())
	}
	return output, nil
}

// prettyJSON returns an indentified JSON bytes.Buffer
func prettyJSON(v any) (bytes.Buffer, error) {
	var out bytes.Buffer

	outputJson, err := json.Marshal(v)
	if err != nil {
		fmt.Printf("[-] ERROR: JSON failure: %v\n", err)
		return out, err
	}

	err = json.Indent(&out, outputJson, "", "  ")
	if err != nil {
		fmt.Printf("json indent error\n")
		return out, err
	}
	// fmt.Printf("%s\n", out.Bytes())
	return out, nil
}

func printJSON(input any) {
	buf, err := prettyJSON(input)
	if err != nil {
		fmt.Printf("[-] ERROR: Failed to prettify JSON\n")
		return
	}
	fmt.Println("")
	fmt.Println("------------------ CUT HERE ------------------")
	fmt.Printf("%s\n", buf.Bytes())
	fmt.Println("------------------ CUT HERE ------------------")
}

func saveJSON(input any, output string) error {
	buf, err := prettyJSON(input)
	if err != nil {
		fmt.Printf("[-] ERROR: Failed to prettify JSON\n")
		return err
	}
	err = os.WriteFile(output, buf.Bytes(), 0644)
	if err != nil {
		fmt.Errorf("[-] ERROR: Failed to write JSON file: %v\n", err)
		return err
	}
	return nil
}

func main() {
	fmt.Println("          ____________   ___    ____     ___")
	fmt.Println("         / __/ ___/ _ | / _ \\  /  _/__  / _/__")
	fmt.Println("        _\\ \\/ /__/ __ |/ ___/ _/ // _ \\/ _/ _ \\")
	fmt.Println("       /___/\\___/_/ |_/_/    /___/_//_/_/ \\___/")
	fmt.Println("(c) fG! 2024 - reverser@put.as - https://reverse.put.as")
	fmt.Printf("SCAP Info v%s.%s generated %s from hash %s\n", Version, Build, Time, GitHash)

	var input string
	var output string
	flag.StringVar(&input, "i", "", "Input SCAP file")
	flag.StringVar(&output, "o", "", "Output JSON file")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.Parse()

	if input == "" {
		fmt.Println("[-] ERROR: Missing input file.")
		return
	}

	stat, err := os.Stat(input)
	if err != nil {
		fmt.Printf("[-] ERROR: Failed to stat file: %v\n", err)
		os.Exit(1)
	}

	if mode := stat.Mode(); mode.IsRegular() {
		data, err := AnalyseFile(input)
		if err != nil {
			fmt.Printf("[-] ERROR: Failed to analyse file: %v\n", err)
			os.Exit(1)
		}
		if output != "" {
			saveJSON(data, output)
		} else {
			printJSON(data)
		}
	} else if mode.IsDir() {
		data, err := AnalyseFolder(input)
		if err != nil {
			fmt.Printf("[-] ERROR: Failed to analyse folder: %v\n", err)
			os.Exit(1)
		}
		if output != "" {
			saveJSON(data, output)
		} else {
			printJSON(data)
		}
	} else {
		fmt.Printf("[-] ERROR: Not sure what the hell target is!\n")
		os.Exit(1)
	}
	fmt.Printf("[+] All done!\n")
}
