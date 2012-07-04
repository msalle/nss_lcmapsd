#ifndef _NSS_LCMAPSD_H
#define _NSS_LCMAPSD_H

#include "nss_lcmapsd_config.h"

#include <sys/types.h>	/* For size_t */
#include <pwd.h>	/* For struct passwd */

/* Default ULR of the LCMAPSd */
#define LCMAPSD_URL     "http://localhost:8008/lcmaps/mapping/rest"

/* Default timeout for the LCMAPSd */
#define LCMAPSD_TIMEOUT 1L

/* Struct containing all options from the config file */
typedef struct lcmapsd_opts_s	{
    char *lcmapsd_conffile;
    char *lcmapsd_url;
    long lcmapsd_timeout;
} lcmapsd_opts_t;


/**
 * Actual nss lookup function trying to do a mapping via a lcmapsd
 */
enum nss_status
_nss_lcmapsd_getpwnam_r (const char *name, struct passwd *result, char *buffer,
                       size_t buflen, int *errnop);


/**
 * Free()s memory in config options
 * \param opts contains the lcmapsd options 
 */
void _nss_lcmapsd_config_free(lcmapsd_opts_t *opts);

/**
 * Parses the config file and stores the values in opts
 * \param opts contains the lcmapsd options
 * \return 0 success, -1 on I/O error, -2 on permission error, -3 on memory
 * error
 */
int _nss_lcmapsd_parse_config(lcmapsd_opts_t *opts);

#endif
