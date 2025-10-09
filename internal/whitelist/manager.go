package whitelist

import (
	"context"
	"sync"

	"github.com/yl2chen/cidranger"
	"go.uber.org/zap"
	"inet.af/netaddr"
)

type WhitelistManager struct {
	ranger cidranger.Ranger
	ctx    context.Context
	mutex  sync.Mutex
}

func NewWhitelistManager() *WhitelistManager {
	return &WhitelistManager{
		ranger: cidranger.NewPCTrieRanger(),
		ctx:    context.Background(),
	}
}

// IsWhitelisted returns true if the IP is in the whitelist.
func (wm *WhitelistManager) IsWhitelisted(ipStr string) bool {
	ip, err := netaddr.ParseIP(ipStr)
	if err != nil {
		zap.L().Warn("Invalid IP for whitelist check", zap.String("ip", ipStr), zap.Error(err))
		return false
	}

	wm.mutex.Lock()
	ranger := wm.ranger
	wm.mutex.Unlock()

	ok, err := ranger.Contains(ip.IPAddr().IP)
	if err != nil {
		zap.L().Error("CIDR check error", zap.Error(err))
		return false
	}
	return ok
}
