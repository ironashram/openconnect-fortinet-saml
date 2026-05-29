/*
 * OpenConnect local per-host overrides — parser.
 * Self-contained: depends only on libc, no openconnect internals.
 */

#include "local_overrides.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int parse_file(const char *path, const char *hostname,
		      struct local_override *out)
{
	FILE *fp;
	char line[512];
	int matched = 0;

	fp = fopen(path, "r");
	if (!fp)
		return 0;

	while (fgets(line, sizeof(line), fp)) {
		char *p = line, *host_start, *host_end;
		char saved;

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0')
			continue;

		host_start = p;
		while (*p && !isspace((unsigned char)*p))
			p++;
		host_end = p;
		saved = *host_end;
		*host_end = '\0';

		if (strcasecmp(host_start, hostname) != 0) {
			*host_end = saved;
			continue;
		}
		*host_end = saved;

		matched = 1;
		p = host_end;

		while (*p) {
			char *flag, saved2;

			while (*p == ' ' || *p == '\t')
				p++;
			if (*p == '\0' || *p == '\n' || *p == '\r' || *p == '#')
				break;

			flag = p;
			while (*p && !isspace((unsigned char)*p) && *p != '#')
				p++;
			saved2 = *p;
			*p = '\0';

			if (!strcmp(flag, "force-saml"))
				out->force_saml = 1;
			else if (!strcmp(flag, "force-ext-browser"))
				out->force_ext_browser = 1;
			else if (!strcmp(flag, "disable-ipv6"))
				out->disable_ipv6 = 1;

			*p = saved2;
		}

		break;
	}

	fclose(fp);
	return matched;
}

int local_overrides_lookup(const char *hostname, struct local_override *out)
{
	const char *xdg, *home;
	char path[1024];

	if (!hostname || !out)
		return 0;

	memset(out, 0, sizeof(*out));

	if (parse_file("/etc/openconnect/local-overrides.conf", hostname, out))
		return 1;

	xdg = getenv("XDG_CONFIG_HOME");
	home = getenv("HOME");

	if (xdg && *xdg) {
		snprintf(path, sizeof(path), "%s/openconnect/local-overrides.conf", xdg);
		if (parse_file(path, hostname, out))
			return 1;
	} else if (home && *home) {
		snprintf(path, sizeof(path), "%s/.config/openconnect/local-overrides.conf", home);
		if (parse_file(path, hostname, out))
			return 1;
	}

	return 0;
}
