package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
)

const (
	DefaultArtNetPort = 6454 // 0x1936
)

var (
	verbose    bool
	nameFilter *regexp.Regexp
)

func main() {
	port := flag.Int("port", DefaultArtNetPort, "UDP port to listen on (default: 6454/0x1936)")
	bindAddr := flag.String("bind", "0.0.0.0", "IP address to bind to")
	namePattern := flag.String("name", "", "Filter by node name (regex)")
	flag.BoolVar(&verbose, "v", false, "Verbose output (show all field details)")
	flag.Parse()

	if *namePattern != "" {
		var err error
		nameFilter, err = regexp.Compile(*namePattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid name regex: %v\n", err)
			os.Exit(1)
		}
	}

	ip := net.ParseIP(*bindAddr)
	if ip == nil {
		fmt.Fprintf(os.Stderr, "Invalid bind address: %s\n", *bindAddr)
		os.Exit(1)
	}

	addr := net.UDPAddr{
		Port: *port,
		IP:   ip,
	}

	conn, err := net.ListenUDP("udp4", &addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen on UDP port %d: %v\n", *port, err)
		fmt.Fprintf(os.Stderr, "You may need to run with sudo or use setcap cap_net_bind_service=+ep\n")
		os.Exit(1)
	}
	defer conn.Close()

	slog.Info("listening", "addr", fmt.Sprintf("%s:%d", *bindAddr, *port))
	if *port != DefaultArtNetPort {
		slog.Warn("non-standard port", "expected", DefaultArtNetPort)
	}

	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			slog.Error("read failed", "error", err)
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		processPacket(packet, remoteAddr)
	}
}

func processPacket(data []byte, src *net.UDPAddr) {
	result := ValidatePacket(data, src)

	// Apply name filter
	if nameFilter != nil {
		name := result.getField("PortName")
		if !nameFilter.MatchString(name) {
			return
		}
	}

	// Build log attributes
	attrs := []any{
		"src", src.IP.String(),
		"size", len(data),
		"type", result.PacketType,
	}

	// Add summary fields based on packet type
	for _, kv := range result.SummaryAttrs() {
		attrs = append(attrs, kv.Key, kv.Value)
	}

	// Add error/warning counts if any
	if len(result.Errors) > 0 {
		attrs = append(attrs, "errors", len(result.Errors))
	}
	if len(result.Warnings) > 0 {
		attrs = append(attrs, "warnings", len(result.Warnings))
	}

	// Log the packet
	if len(result.Errors) > 0 {
		slog.Error("packet", attrs...)
	} else if len(result.Warnings) > 0 {
		slog.Warn("packet", attrs...)
	} else {
		slog.Info("packet", attrs...)
	}

	// Always log individual warnings
	for _, w := range result.Warnings {
		slog.Warn("validation", "src", src.IP.String(), "warning", w)
	}

	// Always log individual errors
	for _, e := range result.Errors {
		slog.Error("validation", "src", src.IP.String(), "error", e)
	}

	// Verbose: log all fields
	if verbose && len(result.Fields) > 0 {
		for _, f := range result.Fields {
			slog.Debug("field", "src", src.IP.String(), "name", f.Name, "value", f.Value)
		}
	}
}
