package policy

import (
	"fmt"
	"time"
)

// Timing profiles trade scan speed against load and tolerance for slow hosts.
// Every value is a fixed, validated constant: no user text reaches Nmap's argv.
const (
	TimingStandard = "standard"
	TimingFastLAN  = "fast-lan"
	TimingPolite   = "polite"
)

// Timing is the resolved pacing for a scan.
type Timing struct {
	Name          string
	NmapT         int           // nmap -T<n>; 0 = leave at nmap's default
	MaxRetries    int           // --max-retries
	MaxRTT        string        // --max-rtt-timeout ("" = default)
	InitRTT       string        // --initial-rtt-timeout ("" = default)
	ScriptTimeout string        // --script-timeout
	RateFactor    int           // percent of the template's max packet rate
	NucleiRate    int           // requests per second
	PrivateOnly   bool          // only valid when every target is private/loopback
	HostTimeout   time.Duration // nmap --host-timeout: gives up on one host so it cannot stall a chunk
}

var timings = map[string]Timing{
	TimingStandard: {Name: TimingStandard, MaxRetries: 2, ScriptTimeout: "60s", RateFactor: 100, NucleiRate: 100, HostTimeout: 20 * time.Minute},
	// For gigabit/home LANs and loopback: tight round-trip bounds and short script
	// timeouts. Slow or heavily loaded hosts may be under-probed; use standard there.
	TimingFastLAN: {Name: TimingFastLAN, NmapT: 4, MaxRetries: 1, MaxRTT: "400ms", InitRTT: "100ms", ScriptTimeout: "15s",
		RateFactor: 200, NucleiRate: 300, PrivateOnly: true, HostTimeout: 8 * time.Minute},
	// For fragile appliances and WAN links.
	TimingPolite: {Name: TimingPolite, NmapT: 2, MaxRetries: 3, ScriptTimeout: "120s", RateFactor: 40, NucleiRate: 25, HostTimeout: 45 * time.Minute},
}

// TimingNames lists the valid profiles.
func TimingNames() []string { return []string{TimingStandard, TimingFastLAN, TimingPolite} }

// ResolveTiming returns the profile for a name ("" means standard).
func ResolveTiming(name string) (Timing, error) {
	if name == "" {
		name = TimingStandard
	}
	t, ok := timings[name]
	if !ok {
		return Timing{}, fmt.Errorf("unknown timing profile %q (%v)", name, TimingNames())
	}
	return t, nil
}
