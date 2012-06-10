#ifndef _NSS_LCMAPSD_H
#define _NSS_LCMAPSD_H

#include "nss_lcmapsd_config.h"

#define	NSS_LCMAPSD_CONFIG  "/tmp/nss_lcmapsd.conf"

/*#define	NSS_LCMAPSD_CONFIG  SYSCONFDIR "/nss_lcmapsd.conf"*/
#define LCMAPSD_URL     "http://localhost:8008/lcmaps/mapping/rest"
#define LCMAPSD_TIMEOUT 3L

typedef struct lcmapsd_opts_s	{
    char *lcmapsd_url;
    int lcmapsd_timeout;
} lcmapsd_opts_t;

#endif
