package obsidian

import "time"

const (
	ProfileFastSecure = "fast-secure"
	ProfileBalanced   = "balanced"
	ProfileStealth    = "stealth"
)

// NormalizeProfile returns a safe known profile name. Empty means fast-secure.
func NormalizeProfile(profile string) string {
	switch profile {
	case ProfileBalanced, ProfileStealth:
		return profile
	default:
		return ProfileFastSecure
	}
}

// ApplyProfile tunes tunnel and obfuscation defaults without weakening crypto.
// Profiles only change performance/obfuscation trade-offs around metadata traffic.
func ApplyProfile(profile string, tc *TunnelConfig, oc *ObfuscationConfig) {
	if tc == nil || oc == nil {
		return
	}
	switch NormalizeProfile(profile) {
	case ProfileStealth:
		tc.Jitter = JitterLight
		tc.NoiseMinInterval = 10 * time.Second
		tc.NoiseMaxInterval = 40 * time.Second
		tc.UseBucketPadding = true
		tc.BucketMTU = 1360
		tc.MaxTrailer = 64
		oc.MaxTrailer = 64
		oc.JunkCount = maxInt(oc.JunkCount, 4)
		oc.JunkMin = maxInt(oc.JunkMin, 96)
		oc.JunkMax = maxInt(oc.JunkMax, 768)
		oc.S1Min, oc.S1Max = maxInt(oc.S1Min, 96), maxInt(oc.S1Max, 384)
		oc.S2Min, oc.S2Max = maxInt(oc.S2Min, 96), maxInt(oc.S2Max, 384)
	case ProfileBalanced:
		tc.Jitter = JitterOff
		tc.DataPadMin = 0
		tc.DataPadMax = 0
		tc.UseBucketPadding = false
		tc.BucketMTU = 1360
		tc.MaxTrailer = 0
		oc.MaxTrailer = 0
	default: // fast-secure
		tc.Jitter = JitterOff
		tc.DataPadMin = 0
		tc.DataPadMax = 0
		tc.UseBucketPadding = false
		tc.BucketMTU = 1360
		tc.MaxTrailer = 0
		oc.MaxTrailer = 0
		oc.JunkCount = maxInt(oc.JunkCount, 3)
		oc.JunkMin = maxInt(oc.JunkMin, 64)
		oc.JunkMax = maxInt(oc.JunkMax, 512)
		oc.S1Min, oc.S1Max = maxInt(oc.S1Min, 64), maxInt(oc.S1Max, 256)
		oc.S2Min, oc.S2Max = maxInt(oc.S2Min, 64), maxInt(oc.S2Max, 256)
		oc.PrePadMax = maxInt(oc.PrePadMax, 64)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
