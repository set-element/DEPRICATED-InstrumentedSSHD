/* $OpenBSD: version.h,v 1.70 2014/02/27 22:57:40 djm Exp $ */

#define SSH_VERSION	"OpenSSH_6.6"

#define SSH_PORTABLE	"p1"
#define SSH_HPN         "-hpn14v2"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN

#ifdef NERSC_MOD
#undef SSH_RELEASE
#define SSH_AUDITING	"NMOD_3.15"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN SSH_AUDITING
#endif /* NERSC_MOD */
