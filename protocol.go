package main

import "fmt"

// ArtNet Protocol Constants from Art-Net 4 Specification

// ArtNetID is the magic identifier at the start of every Art-Net packet
var ArtNetID = [8]byte{'A', 'r', 't', '-', 'N', 'e', 't', 0x00}

// Protocol Version - Current is 14
const (
	ProtocolVersionHi = 0
	ProtocolVersionLo = 14
)

// OpCodes - Table 1 from the spec
type OpCode uint16

const (
	OpPoll            OpCode = 0x2000
	OpPollReply       OpCode = 0x2100
	OpDiagData        OpCode = 0x2300
	OpCommand         OpCode = 0x2400
	OpDataRequest     OpCode = 0x2700
	OpDataReply       OpCode = 0x2800
	OpDmx             OpCode = 0x5000 // Also called OpOutput
	OpNzs             OpCode = 0x5100
	OpSync            OpCode = 0x5200
	OpAddress         OpCode = 0x6000
	OpInput           OpCode = 0x7000
	OpTodRequest      OpCode = 0x8000
	OpTodData         OpCode = 0x8100
	OpTodControl      OpCode = 0x8200
	OpRdm             OpCode = 0x8300
	OpRdmSub          OpCode = 0x8400
	OpVideoSetup      OpCode = 0xa010
	OpVideoPalette    OpCode = 0xa020
	OpVideoData       OpCode = 0xa040
	OpMacMaster       OpCode = 0xf000 // Deprecated
	OpMacSlave        OpCode = 0xf100 // Deprecated
	OpFirmwareMaster  OpCode = 0xf200
	OpFirmwareReply   OpCode = 0xf300
	OpFileTnMaster    OpCode = 0xf400
	OpFileFnMaster    OpCode = 0xf500
	OpFileFnReply     OpCode = 0xf600
	OpIpProg          OpCode = 0xf800
	OpIpProgReply     OpCode = 0xf900
	OpMedia           OpCode = 0x9000
	OpMediaPatch      OpCode = 0x9100
	OpMediaControl    OpCode = 0x9200
	OpMediaCtrlReply  OpCode = 0x9300
	OpTimeCode        OpCode = 0x9700
	OpTimeSync        OpCode = 0x9800
	OpTrigger         OpCode = 0x9900
	OpDirectory       OpCode = 0x9a00
	OpDirectoryReply  OpCode = 0x9b00
)

func (o OpCode) String() string {
	names := map[OpCode]string{
		OpPoll:           "OpPoll",
		OpPollReply:      "OpPollReply",
		OpDiagData:       "OpDiagData",
		OpCommand:        "OpCommand",
		OpDataRequest:    "OpDataRequest",
		OpDataReply:      "OpDataReply",
		OpDmx:            "OpDmx/OpOutput",
		OpNzs:            "OpNzs",
		OpSync:           "OpSync",
		OpAddress:        "OpAddress",
		OpInput:          "OpInput",
		OpTodRequest:     "OpTodRequest",
		OpTodData:        "OpTodData",
		OpTodControl:     "OpTodControl",
		OpRdm:            "OpRdm",
		OpRdmSub:         "OpRdmSub",
		OpVideoSetup:     "OpVideoSetup",
		OpVideoPalette:   "OpVideoPalette",
		OpVideoData:      "OpVideoData",
		OpMacMaster:      "OpMacMaster (Deprecated)",
		OpMacSlave:       "OpMacSlave (Deprecated)",
		OpFirmwareMaster: "OpFirmwareMaster",
		OpFirmwareReply:  "OpFirmwareReply",
		OpFileTnMaster:   "OpFileTnMaster",
		OpFileFnMaster:   "OpFileFnMaster",
		OpFileFnReply:    "OpFileFnReply",
		OpIpProg:         "OpIpProg",
		OpIpProgReply:    "OpIpProgReply",
		OpMedia:          "OpMedia",
		OpMediaPatch:     "OpMediaPatch",
		OpMediaControl:   "OpMediaControl",
		OpMediaCtrlReply: "OpMediaCtrlReply",
		OpTimeCode:       "OpTimeCode",
		OpTimeSync:       "OpTimeSync",
		OpTrigger:        "OpTrigger",
		OpDirectory:      "OpDirectory",
		OpDirectoryReply: "OpDirectoryReply",
	}
	if name, ok := names[o]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04X)", uint16(o))
}

// Minimum packet lengths per spec
const (
	MinArtPollLength      = 14  // Spec: "accept as valid a packet of length 14 bytes or larger"
	MinArtPollReplyLength = 207 // Spec: "accept as valid a packet of length 207 bytes or larger"
)

// NodeReport Codes - Table 3
type NodeReportCode uint16

const (
	RcDebug       NodeReportCode = 0x0000
	RcPowerOk     NodeReportCode = 0x0001
	RcPowerFail   NodeReportCode = 0x0002
	RcSocketWr1   NodeReportCode = 0x0003
	RcParseFail   NodeReportCode = 0x0004
	RcUdpFail     NodeReportCode = 0x0005
	RcShNameOk    NodeReportCode = 0x0006
	RcLoNameOk    NodeReportCode = 0x0007
	RcDmxError    NodeReportCode = 0x0008
	RcDmxUdpFull  NodeReportCode = 0x0009
	RcDmxRxFull   NodeReportCode = 0x000a
	RcSwitchErr   NodeReportCode = 0x000b
	RcConfigErr   NodeReportCode = 0x000c
	RcDmxShort    NodeReportCode = 0x000d
	RcFirmwareFail NodeReportCode = 0x000e
	RcUserFail    NodeReportCode = 0x000f
	RcFactoryRes  NodeReportCode = 0x0010
)

func (n NodeReportCode) String() string {
	names := map[NodeReportCode]string{
		RcDebug:       "RcDebug - Booted in debug mode",
		RcPowerOk:     "RcPowerOk - Power On Tests successful",
		RcPowerFail:   "RcPowerFail - Hardware tests failed at Power On",
		RcSocketWr1:   "RcSocketWr1 - Last UDP truncated (collision?)",
		RcParseFail:   "RcParseFail - Unable to identify last UDP",
		RcUdpFail:     "RcUdpFail - Unable to open UDP Socket",
		RcShNameOk:    "RcShNameOk - Port Name programming successful",
		RcLoNameOk:    "RcLoNameOk - Long Name programming successful",
		RcDmxError:    "RcDmxError - DMX512 receive errors detected",
		RcDmxUdpFull:  "RcDmxUdpFull - Ran out of DMX transmit buffers",
		RcDmxRxFull:   "RcDmxRxFull - Ran out of DMX Rx buffers",
		RcSwitchErr:   "RcSwitchErr - Rx Universe switches conflict",
		RcConfigErr:   "RcConfigErr - Config does not match firmware",
		RcDmxShort:    "RcDmxShort - DMX output short detected",
		RcFirmwareFail: "RcFirmwareFail - Firmware upload failed",
		RcUserFail:    "RcUserFail - User changes ignored (locked)",
		RcFactoryRes:  "RcFactoryRes - Factory reset occurred",
	}
	if name, ok := names[n]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04X)", uint16(n))
}

// Style Codes - Table 4
type StyleCode uint8

const (
	StNode       StyleCode = 0x00
	StController StyleCode = 0x01
	StMedia      StyleCode = 0x02
	StRoute      StyleCode = 0x03
	StBackup     StyleCode = 0x04
	StConfig     StyleCode = 0x05
	StVisual     StyleCode = 0x06
)

func (s StyleCode) String() string {
	names := map[StyleCode]string{
		StNode:       "StNode - DMX to/from Art-Net device",
		StController: "StController - Lighting console",
		StMedia:      "StMedia - Media Server",
		StRoute:      "StRoute - Network routing device",
		StBackup:     "StBackup - Backup device",
		StConfig:     "StConfig - Configuration/diagnostic tool",
		StVisual:     "StVisual - Visualiser",
	}
	if name, ok := names[s]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(s))
}

// Priority Codes - Table 5
type PriorityCode uint8

const (
	DpLow      PriorityCode = 0x10
	DpMed      PriorityCode = 0x40
	DpHigh     PriorityCode = 0x80
	DpCritical PriorityCode = 0xe0
	DpVolatile PriorityCode = 0xf0
)

func (p PriorityCode) String() string {
	names := map[PriorityCode]string{
		DpLow:      "DpLow - Low priority",
		DpMed:      "DpMed - Medium priority",
		DpHigh:     "DpHigh - High priority",
		DpCritical: "DpCritical - Critical priority",
		DpVolatile: "DpVolatile - Volatile (single line display)",
	}
	if name, ok := names[p]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(p))
}

// Port Types bit definitions
const (
	PortTypeOutput  = 0x80 // Bit 7: Can output data from Art-Net
	PortTypeInput   = 0x40 // Bit 6: Can input onto Art-Net
	PortTypeDMX512  = 0x00 // Bits 5-0: Protocol
	PortTypeMIDI    = 0x01
	PortTypeAvab    = 0x02
	PortTypeCMX     = 0x03
	PortTypeADB     = 0x04
	PortTypeArtNet  = 0x05
	PortTypeDALI    = 0x06
)
