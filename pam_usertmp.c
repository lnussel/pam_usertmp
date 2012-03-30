#if 0
set -- gcc -o ${0%%.*}.so -Wall -g -O2 -fPIC -shared $0
echo "$@"
exec "$@"
exit 1
#endif
/*
 * Copyright (C) 2012 SUSE Linux Products GmbH
 *
 * Author: Ludwig Nussel <ludwig.nussel@suse.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <errno.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#ifdef HAVE_GCCVISIBILITY
#  define DLLEXPORT __attribute__ ((visibility("default")))
#  define DLLLOCAL __attribute__ ((visibility("hidden")))
#else
#  define DLLEXPORT
#  define DLLLOCAL
#endif

#ifndef PAM_EXTERN
#  define PAM_EXTERN
#endif

#define DIMOF(x) (sizeof(x)/sizeof(x[0]))

#ifndef _
#define _(x) (x)
#endif

const char* tmppath = "/var/cache/users/";

static void parse_args(const char* type, int argc, const char **argv)
{
	char file[PATH_MAX] = "/etc/security/pam_usertmp.conf";
	int i;

	for(i=0; i < argc; ++i)
	{
		if(!strncmp(argv[i], "file=", 5))
		{
			strncat(file, argv[i]+5, sizeof(file)-1);
		}
	}
	// TODO
}

DLLEXPORT PAM_EXTERN
int pam_sm_open_session(pam_handle_t * pamh, int flags,int argc, const char **argv)
{
	char path[PATH_MAX];
	const void* ptr;
	const char* user;
	char* c;
	int ret = PAM_SUCCESS;
	mode_t old_umask;

	parse_args("session", argc, argv);

	ret = pam_get_item(pamh, PAM_USER, &ptr);
	if(ret != PAM_SUCCESS)
		return PAM_IGNORE;
	else
		user = ptr;

	strcpy(path, tmppath);
	strncat(path, user, sizeof(path)-strlen(tmppath)-1);
	// better safe than sorry, subsitute potential nasty characters
	for (c = path+strlen(tmppath); *c; ++c)
		if (*c == '/' || *c == ':')
			*c = '_';

	old_umask = umask(0);

	if (mkdir(path, 0700) && errno != EEXIST) {
		syslog(LOG_WARNING, "%s: mkdir(%s) failed: %m", __FILE__, path);
		ret = PAM_IGNORE;
		goto out;
	}

	strncat(path, "/tmp", sizeof(path)-strlen(tmppath)-1);

	if (mkdir(path, 0700) && errno != EEXIST) {
		syslog(LOG_WARNING, "%s: mkdir(%s) failed: %m", __FILE__, path);
		ret = PAM_IGNORE;
		goto out;
	}

	ret = pam_misc_setenv(pamh, "TMPDIR", path, 0);
	if(ret != PAM_SUCCESS)
	{
		 ret = PAM_IGNORE;
		 goto out;
	}

out:
	umask(old_umask);
	return ret;
}
