#ifdef __ANDROID__
/*
 * Copyright (c) 2016, Roumen Petrov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"
#include <unistd.h>

/* bionic stub replacement
 *
 * The  function ttyname() returns a pointer to a pathname on success.
 * On error, NULL is returned, and errno is set appropriately.
 */
char*
android_ttyname(int fd) {
	static char buf[PATH_MAX];

	return (android_ttyname_r(fd, buf, sizeof(buf)) == 0)
		? buf
		: NULL;
}


/* bionic stub replacement
 *
 * The function ttyname_r() returns 0 on success, and an error number
 * upon error.
 */
int
android_ttyname_r(int fd, char *buf, size_t buflen) {
	ssize_t k;

	if (buf == NULL) {
		errno = EINVAL;
		return errno;
	}
	if (buflen < 6) { /* "/dev/" + NUL */
		errno = ERANGE;
		return errno;
	}

	if (!isatty(fd)) {
		return errno;
	}

{
	char proc_fd[PATH_MAX];
	snprintf(proc_fd, sizeof(proc_fd), "/proc/self/fd/%d", fd);
	/*NOTE on error content of buf is undefined*/
	k = readlink(proc_fd, buf, buflen);
}

	if (k == -1)
		return errno;

	if ((size_t)k == buflen) {
		errno = ERANGE;
		return errno;
	}
	buf[k] = '\0';
	return 0;
}


/* bionic missing
 *
 * Function endgrent is declared in grp.h but not defined.
 */
void
endgrent(void) {
}

/* bionic missing
 *
 * Function endpwent is declared in pwd.h but not defined.
 */
void
endpwent(void) {
}

/* Fake user for android */
#include "xmalloc.h"
#include <unistd.h>
#include <fcntl.h>
#include <openssl/des.h>
#undef getpwnam
#undef getpwuid


extern char *ssh_progpath;

static struct passwd *fake_passwd = NULL;
static char *ssh_home = NULL;
static char *ssh_shell = NULL;


static void
parse_fake_passwd() {
	char *pw_name;
	char *pw_passwd;
	char *pw_uid;
	char *pw_gid;
	char *pw_gecos;
	char *pw_dir;
	char *pw_shell = NULL;

	int   fd = -1;

{
	char     path[PATH_MAX];

	if (snprintf(path, PATH_MAX, "%s/../" _PATH_PASSWD, ssh_progpath) >= PATH_MAX)
		return;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;
}

{	/* parse password line */
	char buf[1024], *s;

	if (read(fd, buf, sizeof(buf)) <= 0) {
		close(fd);
		return;
	}

	if ((s = strchr(buf, '\r')) != NULL) *s = '\0';
	if ((s = strchr(buf, '\n')) != NULL) *s = '\0';
	if ((s = strchr(buf, '\t')) != NULL) *s = '\0';
	if ((s = strchr(buf, ' ' )) != NULL) *s = '\0';

	s = buf;

	pw_name = s;
	if (*pw_name == '\0') goto parse_err;
	s = strchr(s, ':'); if (s == NULL) goto parse_err;
	*s = '\0';

	pw_passwd = ++s;
	if (*pw_passwd == '\0') goto parse_err;
	s = strchr(s, ':'); if (s == NULL) goto parse_err;
	*s = '\0';

	pw_uid = ++s;
	s = strchr(s, ':'); if (s == NULL) goto parse_err;
	*s = '\0';

	pw_gid = ++s;
	s = strchr(s, ':'); if (s == NULL) goto parse_err;
	*s = '\0';

	pw_gecos= ++s;
	s = strchr(s, ':'); if (s == NULL) goto parse_err;
	*s = '\0';

	pw_dir = ++s;
	if (*pw_dir == '\0') goto parse_err;
	s = strchr(s, ':'); if (s == NULL) goto parse_err;
	*s = '\0';

	pw_shell = ++s;

parse_err:
	close(fd);
}

	if (pw_shell == NULL) return;

{	/* preset password data */
	char *s;

	s = strdup(pw_name);
	if (s != NULL)
		fake_passwd->pw_name = s;

	s = strdup(pw_passwd);
	if (s != NULL)
		fake_passwd->pw_passwd = s;

	(void) pw_uid;
	(void) pw_gid;
	(void) pw_gecos;

	ssh_home = strdup(pw_dir);
	if (ssh_home != NULL)
		fake_passwd->pw_dir = ssh_home;

	if (*pw_shell != '\0')
		ssh_shell = strdup(pw_shell);
	if (ssh_shell != NULL)
		fake_passwd->pw_shell = ssh_shell;
}
}


static void
init_fake_passwd() {

	if (fake_passwd != NULL) return;

{
	struct passwd* pw;
	size_t n;

	pw = getpwuid(getuid());
	if (pw == NULL) return;

	n = sizeof(*fake_passwd);
	fake_passwd = calloc(1, n);
	if (fake_passwd == NULL) return;

	memcpy(fake_passwd, pw, n);
}

	parse_fake_passwd();
}


static struct passwd*
preset_passwd(struct passwd *pw) {
	if (pw == NULL) return NULL;

	if (ssh_home != NULL)
		pw->pw_dir = ssh_home;

	if (ssh_shell != NULL)
		pw->pw_shell = ssh_shell;

	return pw;
}


/* bionic replacement */
struct passwd*
android_getpwnam(const char* name) {
	struct passwd* pw;

	init_fake_passwd();

	if ((fake_passwd != NULL) && (strcmp(name, fake_passwd->pw_name) == 0))
		return fake_passwd;

	pw = getpwnam(name);

	return preset_passwd(pw);
}


/* bionic replacement */
struct passwd*
android_getpwuid(uid_t uid) {
	struct passwd* pw;

	init_fake_passwd();

	if ((fake_passwd != NULL) && (uid == fake_passwd->pw_uid))
		return fake_passwd;

	pw = getpwuid(uid);

	return preset_passwd(pw);
}


#else

static void *empty_translation_unit = &empty_translation_unit;

#endif /*def __ANDROID__*/
