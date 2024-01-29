function FindProxyForURL(url, host) {
// Bypasses
	
// DEFAULT RULE: All other traffic, use below proxies, in fail-over order.
	return "PROXY 127.0.0.1:3128; DIRECT";
}
