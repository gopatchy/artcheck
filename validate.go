package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// ValidationResult holds the results of packet validation
type ValidationResult struct {
	PacketType string
	Fields     []FieldInfo
	Errors     []string
	Warnings   []string
}

// FieldInfo represents a parsed field and its value
type FieldInfo struct {
	Name  string
	Value string
}

func (r *ValidationResult) addField(name, value string) {
	r.Fields = append(r.Fields, FieldInfo{Name: name, Value: value})
}

func (r *ValidationResult) addError(format string, args ...interface{}) {
	r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
}

func (r *ValidationResult) addWarning(format string, args ...interface{}) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

func (r *ValidationResult) getField(name string) string {
	for _, f := range r.Fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

// KV is a key-value pair for logging
type KV struct {
	Key   string
	Value any
}

func (r *ValidationResult) SummaryAttrs() []KV {
	switch r.PacketType {
	case "ArtPoll":
		attrs := []KV{{"flags", r.getField("Flags")}}
		if universes := r.getField("TargetUniverses"); universes != "" {
			attrs = append(attrs, KV{"universes", universes})
		}
		return attrs
	case "ArtPollReply":
		return []KV{
			{"name", r.getField("PortName")},
			{"universes", r.getField("Universes")},
		}
	default:
		return nil
	}
}

// ValidatePacket validates an Art-Net packet against the specification
func ValidatePacket(data []byte, src *net.UDPAddr) *ValidationResult {
	result := &ValidationResult{}

	// Minimum size check - need at least ID (8) + OpCode (2) = 10 bytes
	if len(data) < 10 {
		result.addError("Packet too short: %d bytes (minimum 10 for ID + OpCode)", len(data))
		return result
	}

	// Validate Art-Net ID (Field 1)
	// Spec: "Array of 8 characters, the final character is a null termination.
	//        Value = 'A' 'r' 't' '-' 'N' 'e' 't' 0x00"
	var packetID [8]byte
	copy(packetID[:], data[0:8])
	if packetID != ArtNetID {
		result.addError("Invalid Art-Net ID: got %q, expected %q", string(packetID[:]), string(ArtNetID[:]))
		return result
	}
	result.addField("ID", fmt.Sprintf("%q (valid)", string(packetID[:7]))) // Don't print null

	// OpCode (Field 2) - "Transmitted low byte first"
	opcode := OpCode(binary.LittleEndian.Uint16(data[8:10]))
	result.addField("OpCode", fmt.Sprintf("0x%04X (%s)", uint16(opcode), opcode))

	// Dispatch based on OpCode
	switch opcode {
	case OpPoll:
		result.PacketType = "ArtPoll"
		validateArtPoll(data, src, result)
	case OpPollReply:
		result.PacketType = "ArtPollReply"
		validateArtPollReply(data, src, result)
	default:
		result.PacketType = opcode.String()
	}

	return result
}

// validateArtPoll validates an ArtPoll packet
// Spec: "Consumers of ArtPoll shall accept as valid a packet of length 14 bytes or larger"
func validateArtPoll(data []byte, src *net.UDPAddr, result *ValidationResult) {
	// Minimum length check
	if len(data) < MinArtPollLength {
		result.addError("ArtPoll too short: %d bytes (minimum %d)", len(data), MinArtPollLength)
		return
	}

	// Field 3: ProtVerHi - "High byte of the Art-Net protocol revision number"
	protVerHi := data[10]
	result.addField("ProtVerHi", fmt.Sprintf("%d", protVerHi))
	if protVerHi != 0 {
		result.addWarning("ProtVerHi is %d, expected 0", protVerHi)
	}

	// Field 4: ProtVerLo - "Low byte of the Art-Net protocol revision number. Current value 14.
	//          Controllers should ignore communication with nodes using a protocol version lower than 14."
	protVerLo := data[11]
	result.addField("ProtVerLo", fmt.Sprintf("%d", protVerLo))
	if protVerLo < 14 {
		result.addError("ProtVerLo is %d, minimum required is 14", protVerLo)
	}

	// Field 5: Flags
	flags := data[12]
	result.addField("Flags", fmt.Sprintf("0x%02X", flags))
	validateArtPollFlags(flags, result)

	// Field 6: DiagPriority - "The lowest priority of diagnostics message that should be sent"
	diagPriority := data[13]
	result.addField("DiagPriority", fmt.Sprintf("0x%02X (%s)", diagPriority, PriorityCode(diagPriority)))
	// Value 0x00 is deprecated per spec
	if diagPriority == 0x00 {
		result.addWarning("DiagPriority 0x00 is deprecated")
	}

	// Optional fields (packet may be longer)
	if len(data) >= 18 {
		// Fields 7-10: Target Port Address range (if Targeted Mode enabled)
		targetTopHi := data[14]
		targetTopLo := data[15]
		targetBottomHi := data[16]
		targetBottomLo := data[17]

		targetTop := uint16(targetTopHi)<<8 | uint16(targetTopLo)
		targetBottom := uint16(targetBottomHi)<<8 | uint16(targetBottomLo)

		result.addField("TargetPortAddressTop", fmt.Sprintf("%d (0x%04X)", targetTop, targetTop))
		result.addField("TargetPortAddressBottom", fmt.Sprintf("%d (0x%04X)", targetBottom, targetBottom))

		// Validate target range
		if flags&0x20 != 0 { // Targeted mode enabled
			if targetBottom == targetTop {
				result.addField("TargetUniverses", formatPortAddress(targetBottom))
			} else {
				result.addField("TargetUniverses", fmt.Sprintf("%s to %s", formatPortAddress(targetBottom), formatPortAddress(targetTop)))
			}
			if targetBottom > targetTop {
				result.addError("TargetPortAddressBottom (%d) > TargetPortAddressTop (%d)", targetBottom, targetTop)
			}
			// Port-Address 0 is deprecated
			if targetBottom == 0 {
				result.addWarning("TargetPortAddressBottom is 0 (deprecated)")
			}
			// Max Port-Address is 32767 (15 bits)
			if targetTop > 32767 {
				result.addError("TargetPortAddressTop (%d) exceeds maximum 32767", targetTop)
			}
		}
	}

	if len(data) >= 20 {
		// Fields 11-12: EstaMan
		estaManHi := data[18]
		estaManLo := data[19]
		estaMan := uint16(estaManHi)<<8 | uint16(estaManLo)
		result.addField("EstaMan", fmt.Sprintf("0x%04X", estaMan))
	}

	if len(data) >= 22 {
		// Fields 13-14: OemCode
		oemHi := data[20]
		oemLo := data[21]
		oem := uint16(oemHi)<<8 | uint16(oemLo)
		result.addField("OemCode", fmt.Sprintf("0x%04X", oem))
	}

	// Report actual packet length
	result.addField("PacketLength", fmt.Sprintf("%d bytes", len(data)))
}

// validateArtPollFlags validates the Flags field of ArtPoll
func validateArtPollFlags(flags byte, result *ValidationResult) {
	// Bits 7-6: "Unused, transmit as zero, do not test upon receipt"
	if flags&0xC0 != 0 {
		result.addWarning("Flags bits 7-6 are set (should be zero, but spec says do not test)")
	}

	// Bit 5: Targeted Mode
	if flags&0x20 != 0 {
		result.addField("  Flags.TargetedMode", "Enabled")
	} else {
		result.addField("  Flags.TargetedMode", "Disabled")
	}

	// Bit 4: VLC transmission
	if flags&0x10 != 0 {
		result.addField("  Flags.VLC", "Disabled")
	} else {
		result.addField("  Flags.VLC", "Enabled")
	}

	// Bit 3: Diagnostics unicast/broadcast
	if flags&0x08 != 0 {
		result.addField("  Flags.DiagUnicast", "Unicast (if bit 2 set)")
	} else {
		result.addField("  Flags.DiagUnicast", "Broadcast (if bit 2 set)")
	}

	// Bit 2: Send diagnostics
	if flags&0x04 != 0 {
		result.addField("  Flags.SendDiag", "Yes, send diagnostics")
	} else {
		result.addField("  Flags.SendDiag", "No diagnostics")
	}

	// Bit 1: ArtPollReply on change
	if flags&0x02 != 0 {
		result.addField("  Flags.ReplyOnChange", "Send ArtPollReply on Node condition change")
	} else {
		result.addField("  Flags.ReplyOnChange", "Only reply to ArtPoll/ArtAddress")
	}

	// Bit 0: Deprecated
	if flags&0x01 != 0 {
		result.addWarning("Flags bit 0 is set (deprecated)")
	}
}

// validateArtPollReply validates an ArtPollReply packet
// Spec: "Consumers of ArtPollReply shall accept as valid a packet of length 207 bytes or larger"
func validateArtPollReply(data []byte, src *net.UDPAddr, result *ValidationResult) {
	// Minimum length check
	if len(data) < MinArtPollReplyLength {
		result.addError("ArtPollReply too short: %d bytes (minimum %d)", len(data), MinArtPollReplyLength)
		return
	}

	// Field 3: IP Address[4] - "First array entry is most significant byte of address"
	ipAddr := net.IPv4(data[10], data[11], data[12], data[13])
	result.addField("IPAddress", ipAddr.String())

	// Validate IP matches source (or is bound node)
	if !ipAddr.Equal(src.IP) {
		result.addWarning("Reported IP %s differs from source IP %s (may be bound node)", ipAddr, src.IP)
	}

	// Field 4: Port - "The Port is always 0x1936. Transmitted low byte first."
	port := binary.LittleEndian.Uint16(data[14:16])
	result.addField("Port", fmt.Sprintf("0x%04X (%d)", port, port))
	if port != 0x1936 {
		result.addError("Port must be 0x1936, got 0x%04X", port)
	}

	// Field 5-6: VersInfo - Firmware revision
	versInfoH := data[16]
	versInfoL := data[17]
	result.addField("FirmwareVersion", fmt.Sprintf("%d.%d", versInfoH, versInfoL))

	// Field 7: NetSwitch - "Bits 14-8 of the 15 bit Port-Address"
	netSwitch := data[18] & 0x7F // Bottom 7 bits
	result.addField("NetSwitch", fmt.Sprintf("%d (0x%02X)", netSwitch, netSwitch))

	// Field 8: SubSwitch - "Bits 7-4 of the 15 bit Port-Address"
	subSwitch := data[19] & 0x0F // Bottom 4 bits
	result.addField("SubSwitch", fmt.Sprintf("%d (0x%02X)", subSwitch, subSwitch))

	// Field 9-10: Oem code
	oemHi := data[20]
	oemLo := data[21]
	oem := uint16(oemHi)<<8 | uint16(oemLo)
	result.addField("OemCode", fmt.Sprintf("0x%04X", oem))

	// Field 11: UBEA Version
	ubeaVersion := data[22]
	result.addField("UbeaVersion", fmt.Sprintf("%d", ubeaVersion))

	// Field 12: Status1
	status1 := data[23]
	result.addField("Status1", fmt.Sprintf("0x%02X", status1))
	validateStatus1(status1, result)

	// Field 13-14: ESTA Manufacturer Code (Lo byte first in struct, but Hi byte at offset 24)
	estaManLo := data[24]
	estaManHi := data[25]
	estaMan := uint16(estaManHi)<<8 | uint16(estaManLo)
	result.addField("EstaMan", fmt.Sprintf("0x%04X", estaMan))

	// Field 15: PortName[18] - Null terminated, max 17 chars + null
	portName := extractNullTerminatedString(data[26:44], 18)
	result.addField("PortName", portName)
	if len(portName) > 17 {
		result.addError("PortName exceeds 17 characters")
	}

	// Field 16: LongName[64] - Null terminated, max 63 chars + null
	longName := extractNullTerminatedString(data[44:108], 64)
	result.addField("LongName", longName)
	if len(longName) > 63 {
		result.addError("LongName exceeds 63 characters")
	}

	// Field 17: NodeReport[64] - Format: "#xxxx [yyyy] zzzzz..."
	nodeReport := extractNullTerminatedString(data[108:172], 64)
	result.addField("NodeReport", fmt.Sprintf("%q", nodeReport))
	validateNodeReport(nodeReport, result)

	// Field 18-19: NumPorts
	numPortsHi := data[172]
	numPortsLo := data[173]
	result.addField("NumPortsHi", fmt.Sprintf("%d", numPortsHi))
	result.addField("NumPortsLo", fmt.Sprintf("%d", numPortsLo))
	if numPortsHi != 0 {
		result.addWarning("NumPortsHi is %d (reserved for future, expected 0)", numPortsHi)
	}
	if numPortsLo > 4 {
		result.addError("NumPortsLo is %d (maximum is 4)", numPortsLo)
	}

	// Field 20: PortTypes[4]
	result.addField("PortTypes", fmt.Sprintf("[0x%02X, 0x%02X, 0x%02X, 0x%02X]",
		data[174], data[175], data[176], data[177]))
	for i := 0; i < 4; i++ {
		validatePortType(data[174+i], i, result)
	}

	// Field 21: GoodInput[4]
	result.addField("GoodInput", fmt.Sprintf("[0x%02X, 0x%02X, 0x%02X, 0x%02X]",
		data[178], data[179], data[180], data[181]))
	for i := 0; i < 4; i++ {
		validateGoodInput(data[178+i], i, result)
	}

	// Field 22: GoodOutputA[4]
	result.addField("GoodOutputA", fmt.Sprintf("[0x%02X, 0x%02X, 0x%02X, 0x%02X]",
		data[182], data[183], data[184], data[185]))
	for i := 0; i < 4; i++ {
		validateGoodOutputA(data[182+i], i, result)
	}

	// Field 23: SwIn[4] - Input universe addresses
	result.addField("SwIn", fmt.Sprintf("[%d, %d, %d, %d]",
		data[186]&0x0F, data[187]&0x0F, data[188]&0x0F, data[189]&0x0F))

	// Field 24: SwOut[4] - Output universe addresses
	result.addField("SwOut", fmt.Sprintf("[%d, %d, %d, %d]",
		data[190]&0x0F, data[191]&0x0F, data[192]&0x0F, data[193]&0x0F))

	// Calculate full Port-Addresses and collect universes
	var universes []string
	for i := 0; i < int(numPortsLo); i++ {
		swIn := data[186+i] & 0x0F
		swOut := data[190+i] & 0x0F
		inAddr := uint16(netSwitch)<<8 | uint16(subSwitch)<<4 | uint16(swIn)
		outAddr := uint16(netSwitch)<<8 | uint16(subSwitch)<<4 | uint16(swOut)
		result.addField(fmt.Sprintf("  Port %d Input Address", i), fmt.Sprintf("%d", inAddr))
		result.addField(fmt.Sprintf("  Port %d Output Address", i), fmt.Sprintf("%d", outAddr))

		// Collect active universes for summary - format: "net:subnet:universe (portaddr)"
		if data[174+i]&PortTypeInput != 0 {
			universes = append(universes, fmt.Sprintf("in %d:%d:%d (%d)", netSwitch, subSwitch, swIn, inAddr))
		}
		if data[174+i]&PortTypeOutput != 0 {
			universes = append(universes, fmt.Sprintf("out %d:%d:%d (%d)", netSwitch, subSwitch, swOut, outAddr))
		}

		// Port-Address 0 is deprecated
		if inAddr == 0 && data[174+i]&PortTypeInput != 0 {
			result.addWarning("Port %d Input Address is 0 (deprecated)", i)
		}
		if outAddr == 0 && data[174+i]&PortTypeOutput != 0 {
			result.addWarning("Port %d Output Address is 0 (deprecated)", i)
		}
	}
	if len(universes) > 0 {
		result.addField("Universes", strings.Join(universes, ", "))
	} else {
		result.addField("Universes", "none")
	}

	// Field 25: AcnPriority
	acnPriority := data[194]
	result.addField("AcnPriority", fmt.Sprintf("%d", acnPriority))
	if acnPriority > 200 {
		result.addWarning("AcnPriority %d exceeds recommended max of 200", acnPriority)
	}

	// Field 26: SwMacro
	swMacro := data[195]
	result.addField("SwMacro", fmt.Sprintf("0x%02X", swMacro))

	// Field 27: SwRemote
	swRemote := data[196]
	result.addField("SwRemote", fmt.Sprintf("0x%02X", swRemote))

	// Fields 28-30: Spare (should be zero)
	for i := 0; i < 3; i++ {
		if data[197+i] != 0 {
			result.addWarning("Spare byte at offset %d is 0x%02X (should be 0)", 197+i, data[197+i])
		}
	}

	// Field 31: Style
	style := StyleCode(data[200])
	result.addField("Style", fmt.Sprintf("0x%02X (%s)", uint8(style), style))
	if style > StVisual {
		result.addWarning("Unknown Style code 0x%02X", uint8(style))
	}

	// Field 32-37: MAC Address
	mac := net.HardwareAddr(data[201:207])
	result.addField("MAC", mac.String())
	// Check if MAC is all zeros (not able to supply)
	allZero := true
	for _, b := range data[201:207] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		result.addField("  MAC Note", "All zeros (node cannot supply MAC)")
	}

	// Optional extended fields (if packet is longer than minimum 207)
	if len(data) >= 211 {
		// Field 38: BindIp[4]
		bindIP := net.IPv4(data[207], data[208], data[209], data[210])
		result.addField("BindIP", bindIP.String())
	}

	if len(data) >= 212 {
		// Field 39: BindIndex
		bindIndex := data[211]
		result.addField("BindIndex", fmt.Sprintf("%d", bindIndex))
		if bindIndex == 0 {
			result.addField("  BindIndex Note", "0 or 1 means root device")
		}
	}

	if len(data) >= 213 {
		// Field 40: Status2
		status2 := data[212]
		result.addField("Status2", fmt.Sprintf("0x%02X", status2))
		validateStatus2(status2, result)
	}

	if len(data) >= 217 {
		// Field 41: GoodOutputB[4]
		result.addField("GoodOutputB", fmt.Sprintf("[0x%02X, 0x%02X, 0x%02X, 0x%02X]",
			data[213], data[214], data[215], data[216]))
		for i := 0; i < 4; i++ {
			validateGoodOutputB(data[213+i], i, result)
		}
	}

	if len(data) >= 218 {
		// Field 42: Status3
		status3 := data[217]
		result.addField("Status3", fmt.Sprintf("0x%02X", status3))
		validateStatus3(status3, result)
	}

	if len(data) >= 224 {
		// Field 43-48: DefaultResponderUID[6]
		uid := data[218:224]
		result.addField("DefaultResponderUID", fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
			uid[0], uid[1], uid[2], uid[3], uid[4], uid[5]))
	}

	if len(data) >= 226 {
		// Field 49-50: User
		userHi := data[224]
		userLo := data[225]
		result.addField("User", fmt.Sprintf("0x%02X%02X", userHi, userLo))
	}

	if len(data) >= 228 {
		// Field 51-52: RefreshRate
		refreshRateHi := data[226]
		refreshRateLo := data[227]
		refreshRate := uint16(refreshRateHi)<<8 | uint16(refreshRateLo)
		result.addField("RefreshRate", fmt.Sprintf("%d Hz", refreshRate))
		if refreshRate > 0 && refreshRate < 44 {
			result.addField("  RefreshRate Note", "0-44 means max DMX512 rate of 44Hz")
		}
	}

	if len(data) >= 229 {
		// Field 53: BackgroundQueuePolicy
		bqPolicy := data[228]
		result.addField("BackgroundQueuePolicy", fmt.Sprintf("%d", bqPolicy))
		validateBackgroundQueuePolicy(bqPolicy, result)
	}

	// Report actual packet length
	result.addField("PacketLength", fmt.Sprintf("%d bytes", len(data)))
}

func validateStatus1(status byte, result *ValidationResult) {
	// Bits 7-6: Indicator state
	indState := (status >> 6) & 0x03
	indStates := []string{"Unknown", "Locate/Identify Mode", "Mute Mode", "Normal Mode"}
	result.addField("  Status1.Indicator", indStates[indState])

	// Bits 5-4: Port-Address Programming Authority
	progAuth := (status >> 4) & 0x03
	progAuths := []string{"Unknown", "Front panel controls", "Network/Web programmed", "Not used"}
	result.addField("  Status1.ProgAuthority", progAuths[progAuth])
	if progAuth == 3 {
		result.addWarning("Status1 ProgAuthority value 11 is 'Not used'")
	}

	// Bit 3: Not implemented
	if status&0x08 != 0 {
		result.addWarning("Status1 bit 3 is set (should be zero)")
	}

	// Bit 2: Boot mode
	if status&0x04 != 0 {
		result.addField("  Status1.BootMode", "Booted from ROM")
	} else {
		result.addField("  Status1.BootMode", "Normal firmware boot (flash)")
	}

	// Bit 1: RDM capable
	if status&0x02 != 0 {
		result.addField("  Status1.RDM", "Capable")
	} else {
		result.addField("  Status1.RDM", "Not capable")
	}

	// Bit 0: UBEA present
	if status&0x01 != 0 {
		result.addField("  Status1.UBEA", "Present")
	} else {
		result.addField("  Status1.UBEA", "Not present or corrupt")
	}
}

func validateStatus2(status byte, result *ValidationResult) {
	// Bit 7: RDM control via ArtAddress
	if status&0x80 != 0 {
		result.addField("  Status2.RDMControl", "Supports RDM control via ArtAddress")
	}

	// Bit 6: Output style switching
	if status&0x40 != 0 {
		result.addField("  Status2.OutputStyle", "Supports output style switching")
	}

	// Bit 5: Squawking
	if status&0x20 != 0 {
		result.addField("  Status2.Squawking", "Yes")
	}

	// Bit 4: Art-Net/sACN switching
	if status&0x10 != 0 {
		result.addField("  Status2.ArtNetSacn", "Can switch between Art-Net and sACN")
	}

	// Bit 3: 15-bit Port-Address
	if status&0x08 != 0 {
		result.addField("  Status2.PortAddress", "Supports 15-bit (Art-Net 3/4)")
	} else {
		result.addField("  Status2.PortAddress", "Supports 8-bit only (Art-Net II)")
	}

	// Bit 2: DHCP capable
	if status&0x04 != 0 {
		result.addField("  Status2.DHCP", "Capable")
	} else {
		result.addField("  Status2.DHCP", "Not capable")
	}

	// Bit 1: DHCP configured
	if status&0x02 != 0 {
		result.addField("  Status2.DHCPConfig", "IP is DHCP configured")
	} else {
		result.addField("  Status2.DHCPConfig", "IP is manually configured")
	}

	// Bit 0: Web browser config
	if status&0x01 != 0 {
		result.addField("  Status2.WebConfig", "Supports web browser configuration")
	}
}

func validateStatus3(status byte, result *ValidationResult) {
	// Bits 7-6: Failsafe state
	failsafe := (status >> 6) & 0x03
	failsafes := []string{"Hold last state", "All outputs to zero", "All outputs to full", "Playback failsafe scene"}
	result.addField("  Status3.Failsafe", failsafes[failsafe])

	// Bit 5: Programmable failsafe
	if status&0x20 != 0 {
		result.addField("  Status3.ProgFailsafe", "Supported")
	}

	// Bit 4: LLRP support
	if status&0x10 != 0 {
		result.addField("  Status3.LLRP", "Supported")
	}

	// Bit 3: Port direction switching
	if status&0x08 != 0 {
		result.addField("  Status3.PortSwitch", "Supports port direction switching")
	}

	// Bit 2: RDMnet support
	if status&0x04 != 0 {
		result.addField("  Status3.RDMnet", "Supported")
	}

	// Bit 1: BackgroundQueue supported
	if status&0x02 != 0 {
		result.addField("  Status3.BackgroundQueue", "Supported")
	}

	// Bit 0: Background discovery control
	if status&0x01 != 0 {
		result.addField("  Status3.BgDiscoveryCtrl", "Can be disabled via ArtAddress")
	}
}

func validatePortType(pt byte, portNum int, result *ValidationResult) {
	prefix := fmt.Sprintf("  PortType[%d]", portNum)

	if pt&PortTypeOutput != 0 {
		result.addField(prefix+".Output", "Can output from Art-Net")
	}
	if pt&PortTypeInput != 0 {
		result.addField(prefix+".Input", "Can input to Art-Net")
	}

	protocol := pt & 0x3F
	protocols := map[byte]string{
		0x00: "DMX512",
		0x01: "MIDI",
		0x02: "Avab",
		0x03: "Colortran CMX",
		0x04: "ADB 62.5",
		0x05: "Art-Net",
		0x06: "DALI",
	}
	if name, ok := protocols[protocol]; ok {
		result.addField(prefix+".Protocol", name)
	} else {
		result.addField(prefix+".Protocol", fmt.Sprintf("Unknown (0x%02X)", protocol))
	}
}

func validateGoodInput(gi byte, portNum int, result *ValidationResult) {
	prefix := fmt.Sprintf("  GoodInput[%d]", portNum)

	if gi&0x80 != 0 {
		result.addField(prefix+".DataReceived", "Yes")
	}
	if gi&0x40 != 0 {
		result.addField(prefix+".TestPackets", "Includes DMX512 test packets")
	}
	if gi&0x20 != 0 {
		result.addField(prefix+".SIPs", "Includes DMX512 SIPs")
	}
	if gi&0x10 != 0 {
		result.addField(prefix+".TextPackets", "Includes DMX512 text packets")
	}
	if gi&0x08 != 0 {
		result.addField(prefix+".Disabled", "Yes")
	}
	if gi&0x04 != 0 {
		result.addField(prefix+".Errors", "Receive errors detected")
	}
	// Bit 1 unused
	if gi&0x02 != 0 {
		result.addWarning("GoodInput[%d] bit 1 is set (should be zero)", portNum)
	}
	if gi&0x01 != 0 {
		result.addField(prefix+".ConvertTo", "sACN")
	} else {
		result.addField(prefix+".ConvertTo", "Art-Net")
	}
}

func validateGoodOutputA(go_ byte, portNum int, result *ValidationResult) {
	prefix := fmt.Sprintf("  GoodOutputA[%d]", portNum)

	if go_&0x80 != 0 {
		result.addField(prefix+".DataOutput", "ArtDmx or sACN being output as DMX512")
	}
	if go_&0x40 != 0 {
		result.addField(prefix+".TestPackets", "Includes DMX512 test packets")
	}
	if go_&0x20 != 0 {
		result.addField(prefix+".SIPs", "Includes DMX512 SIPs")
	}
	if go_&0x10 != 0 {
		result.addField(prefix+".TextPackets", "Includes DMX512 text packets")
	}
	if go_&0x08 != 0 {
		result.addField(prefix+".Merging", "Yes")
	}
	if go_&0x04 != 0 {
		result.addField(prefix+".ShortDetected", "DMX output short on power up")
	}
	if go_&0x02 != 0 {
		result.addField(prefix+".MergeMode", "LTP")
	} else {
		result.addField(prefix+".MergeMode", "HTP")
	}
	if go_&0x01 != 0 {
		result.addField(prefix+".ConvertFrom", "sACN")
	} else {
		result.addField(prefix+".ConvertFrom", "Art-Net")
	}
}

func validateGoodOutputB(gob byte, portNum int, result *ValidationResult) {
	prefix := fmt.Sprintf("  GoodOutputB[%d]", portNum)

	if gob&0x80 != 0 {
		result.addField(prefix+".RDM", "Disabled")
	} else {
		result.addField(prefix+".RDM", "Enabled")
	}

	if gob&0x40 != 0 {
		result.addField(prefix+".OutputStyle", "Continuous")
	} else {
		result.addField(prefix+".OutputStyle", "Delta")
	}

	if gob&0x20 != 0 {
		result.addField(prefix+".Discovery", "Not running")
	} else {
		result.addField(prefix+".Discovery", "Running")
	}

	if gob&0x10 != 0 {
		result.addField(prefix+".BgDiscovery", "Disabled")
	} else {
		result.addField(prefix+".BgDiscovery", "Enabled")
	}

	// Bits 3-0 should be zero
	if gob&0x0F != 0 {
		result.addWarning("GoodOutputB[%d] bits 3-0 are 0x%X (should be zero)", portNum, gob&0x0F)
	}
}

func validateNodeReport(report string, result *ValidationResult) {
	// Format should be: "#xxxx [yyyy] zzzzz..."
	if report == "" {
		return
	}

	if !strings.HasPrefix(report, "#") {
		result.addWarning("NodeReport should start with '#'")
		return
	}

	// Try to parse format
	if len(report) < 7 {
		result.addWarning("NodeReport too short for expected format")
		return
	}

	// Extract status code (xxxx)
	if len(report) >= 5 {
		codeStr := report[1:5]
		var code uint16
		if _, err := fmt.Sscanf(codeStr, "%04x", &code); err == nil {
			result.addField("  NodeReport.Code", fmt.Sprintf("0x%04X (%s)", code, NodeReportCode(code)))
		}
	}

	// Look for counter [yyyy]
	if bracketStart := strings.Index(report, "["); bracketStart != -1 {
		if bracketEnd := strings.Index(report[bracketStart:], "]"); bracketEnd != -1 {
			counter := report[bracketStart+1 : bracketStart+bracketEnd]
			result.addField("  NodeReport.Counter", counter)
		}
	}
}

func validateBackgroundQueuePolicy(policy byte, result *ValidationResult) {
	policies := map[byte]string{
		0:   "Collect using STATUS_NONE",
		1:   "Collect using STATUS_ADVISORY",
		2:   "Collect using STATUS_WARNING",
		3:   "Collect using STATUS_ERROR",
		4:   "Collection disabled",
	}

	if name, ok := policies[policy]; ok {
		result.addField("  BQPolicy", name)
	} else if policy >= 5 && policy <= 250 {
		result.addField("  BQPolicy", fmt.Sprintf("Manufacturer defined (%d)", policy))
	} else {
		result.addField("  BQPolicy", fmt.Sprintf("Reserved (%d)", policy))
	}
}

func extractNullTerminatedString(data []byte, maxLen int) string {
	for i := 0; i < len(data) && i < maxLen; i++ {
		if data[i] == 0 {
			return string(data[:i])
		}
	}
	return string(data[:maxLen])
}

// formatPortAddress formats a 15-bit port address as "net:subnet:universe (n)"
func formatPortAddress(addr uint16) string {
	net := (addr >> 8) & 0x7F
	subnet := (addr >> 4) & 0x0F
	universe := addr & 0x0F
	return fmt.Sprintf("%d:%d:%d (%d)", net, subnet, universe, addr)
}
