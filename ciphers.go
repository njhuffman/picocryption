package picocryption


const resetNonceAt = int64(60 * (1 << 30))

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

