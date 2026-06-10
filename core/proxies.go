package core

import (
	"io/ioutil"
	"strings"

	"github.com/kgretzky/evilginx2/log"
)

func ReadProxyList(path string) []string {
	dat, err := ioutil.ReadFile(path + "/proxies.txt")
	if err != nil {
		log.Warning("no proxies.txt found: %v", err)
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(dat)), "\n")
	var proxies []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Normalize: if no scheme, assume socks5://
		if !strings.Contains(line, "://") {
			line = "socks5://" + line
		}
		proxies = append(proxies, line)
	}

	if len(proxies) > 0 {
		log.Info("loaded %d proxies from proxies.txt", len(proxies))
	}
	return proxies
}
