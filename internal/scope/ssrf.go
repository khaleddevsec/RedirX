package scope

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

var (
	ErrDisallowedHost      = errors.New("host is outside allowed scope")
	ErrPrivateIPBlocked    = errors.New("redirect or target resolved to private/reserved IP address (SSRF protection)")
	ErrCloudMetadataBlocked = errors.New("cloud metadata endpoint blocked")
)

// List of CIDR blocks that are private, reserved, loopback, or cloud-internal.
var blockedCIDRs = []string{
	"0.0.0.0/8",          // Current network
	"10.0.0.0/8",          // RFC 1918 Private
	"100.64.0.0/10",       // Carrier-grade NAT
	"127.0.0.0/8",         // Loopback
	"169.254.0.0/16",      // Link-local / AWS / GCP / Azure metadata
	"172.16.0.0/12",       // RFC 1918 Private
	"192.0.0.0/24",        // IETF Protocol Assignments
	"192.0.2.0/24",        // TEST-NET-1 (Documentation)
	"192.168.0.0/16",      // RFC 1918 Private
	"198.18.0.0/15",       // Benchmarking
	"198.51.100.0/24",     // TEST-NET-2 (Documentation)
	"203.0.113.0/24",      // TEST-NET-3 (Documentation)
	"224.0.0.0/4",         // Multicast
	"240.0.0.0/4",         // Reserved
	"255.255.255.255/32",  // Broadcast
	"::/128",              // Unspecified
	"::1/128",             // Loopback
	"fc00::/7",            // Unique Local Address (ULA)
	"fe80::/10",           // Link-local unicast
	"2001:db8::/32",       // Documentation
}

var parsedBlockedCIDRs []*net.IPNet

func init() {
	for _, cidr := range blockedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedBlockedCIDRs = append(parsedBlockedCIDRs, ipNet)
		}
	}
}

// IsPrivateOrReservedIP checks whether an IP is loopback, link-local, private, or metadata.
func IsPrivateOrReservedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Native standard library checks
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	// CIDR check for extended ranges (CGNAT, test nets, cloud metadata)
	for _, block := range parsedBlockedCIDRs {
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

// IsCloudMetadataHost checks if the hostname explicitly matches known metadata domains.
func IsCloudMetadataHost(hostname string) bool {
	h := strings.ToLower(strings.TrimSpace(hostname))
	switch h {
	case "metadata.google.internal",
		"metadata.goog",
		"169.254.169.254",
		"instance-data",
		"metadata":
		return true
	}
	return false
}

// ValidateIPs resolves the host and verifies none of its IPs are private/reserved.
func ValidateHostIPs(ctx context.Context, hostname string, resolver *net.Resolver) error {
	if IsCloudMetadataHost(hostname) {
		return ErrCloudMetadataBlocked
	}

	// If hostname is directly an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		if IsPrivateOrReservedIP(ip) {
			return fmt.Errorf("%w: %s", ErrPrivateIPBlocked, ip.String())
		}
		return nil
	}

	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ips, err := resolver.LookupIP(ctx, "ip", hostname)
	if err != nil {
		return err
	}

	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses resolved for host %q", hostname)
	}

	for _, ip := range ips {
		if IsPrivateOrReservedIP(ip) {
			return fmt.Errorf("%w: %s resolved to %s", ErrPrivateIPBlocked, hostname, ip.String())
		}
	}

	return nil
}

// ValidateURLForSSRF checks both the parsed URL host and its resolved IP addresses.
func ValidateURLForSSRF(ctx context.Context, rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("empty hostname in URL: %s", rawURL)
	}

	return ValidateHostIPs(ctx, host, nil)
}

// SafeDialer returns a net.Dialer that resolves DNS and validates IP before connecting.
// This prevents DNS rebinding attacks where a domain resolves to a public IP first,
// and then resolves to 127.0.0.1 or 169.254.169.254 upon connection.
func NewSafeDialContext(timeout time.Duration, enforceSSRF bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		if enforceSSRF {
			if IsCloudMetadataHost(host) {
				return nil, ErrCloudMetadataBlocked
			}

			// Resolve host
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}

			var safeIP net.IP
			for _, ip := range ips {
				if IsPrivateOrReservedIP(ip) {
					return nil, fmt.Errorf("%w: %s resolved to %s", ErrPrivateIPBlocked, host, ip.String())
				}
				if safeIP == nil {
					safeIP = ip
				}
			}

			if safeIP == nil {
				return nil, fmt.Errorf("no valid public IP address resolved for host %s", host)
			}

			// Connect directly to the validated IP to defeat DNS rebinding
			safeAddr := net.JoinHostPort(safeIP.String(), port)
			return dialer.DialContext(ctx, network, safeAddr)
		}

		return dialer.DialContext(ctx, network, addr)
	}
}

