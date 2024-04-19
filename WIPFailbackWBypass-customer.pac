function FindProxyForURL(url, host) {
	// Bypasses
		if(shExpMatch(host, "jamf.customer.com") || 
		shExpMatch(host, "zscaler.com") || 
		shExpMatch(host, "zscloud.net") || 
		shExpMatch(host, "certauth.login.microsoftonline.com") || 
		shExpMatch(host, "manage.microsoft.com") || 
		shExpMatch(host, "networking.apple") || 
		shExpMatch(host, "autologon.microsoft.us") || 
		shExpMatch(host, "autologon.microsoftazuread-sso.com") || 
		shExpMatch(host, "certauth.login.microsoftonline.com") || 
		shExpMatch(host, "device.login.microsoftonline.com") || 
		shExpMatch(host, "enterpriseregistration.windows.net") || 
		shExpMatch(host, "graph.microsoft.com") || 
		shExpMatch(host, "login.chinacloudapi.cn") || 
		shExpMatch(host, "login.microsoft.com") || 
		shExpMatch(host, "login.microsoftonline.com") || 
		shExpMatch(host, "login.microsoftonline.us") || 
		shExpMatch(host, "login.partner.microsoftonline.cn") || 
		shExpMatch(host, "login-us.microsoftonline.com") || 
		shExpMatch(host, "manage.microsoft.com") || 
		shExpMatch(host, "sts.windows.net") || 
		shExpMatch(host, "teams.microsoft.com") )
		return "DIRECT";
	
	// DEFAULT RULE: All other traffic, use below proxies, in fail-over order.
		return "PROXY 127.0.0.1:3128; DIRECT";
	}
