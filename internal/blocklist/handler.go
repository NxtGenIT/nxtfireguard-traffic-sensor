package blocklist

import "github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"

func GetBlocklists() []types.Blocklist {
	blocklistMutex.RLock()
	defer blocklistMutex.RUnlock()
	return storedBlocklists
}
