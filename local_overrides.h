/*
 * OpenConnect local per-host overrides.
 *
 * This module is owned by the fork and contains NO upstream code.
 * Kept in its own translation unit so upstream syncs are minimal-conflict:
 * only one short block in fortinet.c references it.
 *
 * Config: /etc/openconnect/local-overrides.conf
 *   (falls back to $XDG_CONFIG_HOME/openconnect/local-overrides.conf
 *    or ~/.config/openconnect/local-overrides.conf)
 *
 * Format: one host per line, optionally followed by space-separated flags.
 * Lines starting with '#' and blank lines are ignored.
 *   <hostname>  [force-saml]  [force-ext-browser]  [disable-ipv6]
 *
 * Hostname comparison is case-insensitive. First match wins.
 */

#ifndef __OPENCONNECT_LOCAL_OVERRIDES_H__
#define __OPENCONNECT_LOCAL_OVERRIDES_H__

struct local_override {
	int force_saml;          /* set saml_login_port to default for this host */
	int force_ext_browser;   /* skip embedded webview, use external browser  */
	int disable_ipv6;        /* disable IPv6 advertisement during VPN negot. */
};

/*
 * Returns 1 if hostname matched a config entry and *out is populated.
 * Returns 0 otherwise (or if hostname/out is NULL, or no config file present).
 */
int local_overrides_lookup(const char *hostname, struct local_override *out);

#endif /* __OPENCONNECT_LOCAL_OVERRIDES_H__ */
