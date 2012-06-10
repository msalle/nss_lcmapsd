#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "nss_lcmapsd.h"


static int _nss_lcmapsd_read_conf_file(char **buffer)   {
    char *buf;
    int rc=0,fd=0;
    struct stat fstatbuf;

    /* initialize buffer */
    buf=NULL;

    /* open file */
    if ( (fd=open(NSS_LCMAPSD_CONFIG, O_RDONLY))==-1 ||
	 fstat(fd, &fstatbuf) )
	return -1;  /* I/O error */

    /* basic checks. TODO: safeopen */
    if (!S_ISREG(fstatbuf.st_mode) ||	/* regular file? */
//	fstatbuf.st_uid!=0 ||		/* root-owned? */
	(fstatbuf.st_mode & S_IWGRP) || /* unwriteable group? */
	(fstatbuf.st_mode & S_IWOTH))	{ /* unwriteable others? */
	rc=-2;
	goto conf_failed;
    }

    /* malloc buffer */
    if ( (buf=(char*)malloc(fstatbuf.st_size))==NULL )	{
	rc=-3;
	goto conf_failed;
    }

    /* read config */
    if ( read(fd, buf, fstatbuf.st_size)<=0 )	{
	rc=-1;
	goto conf_failed;
    }
    rc=0;
    close(fd);
    *buffer=buf;
    return rc;

conf_failed:
    if (buf)	free(buf);
    if (fd>0)	close(fd);

    return rc;
}

static char *_nss_lcmapsd_conf_value(const char *buf, const char *option)   {
    char *value=NULL;
    int optlen,pos=0,pos2,pos3,len;

    if (buf==NULL || option==NULL) return NULL;
    optlen=strlen(option);
    do {
	/* Find next non-whitespace */
	while (buf[pos]==' ' || buf[pos]=='\t' || buf[pos]=='\n')
	    pos++;

	if (buf[pos]=='\0')
	    return NULL;

	if (strncmp(&(buf[pos]),option,optlen)==0 &&
	    (buf[pos+optlen]==' ' || buf[pos+optlen]=='\t' ||
	     buf[pos+optlen]=='='))
	{   /* Found option */
	    /* Find start of value */
	    pos2=pos+optlen;
	    while ( buf[pos2]==' ' || buf[pos2]=='\t')
		pos2++;
	    if (buf[pos2]=='=') {
		do {
		    pos2++;
		} while (buf[pos2]==' ' || buf[pos2]=='\t');
	    }
	    /* Find end of value */
	    pos3=pos2;
	    while (buf[pos3]!='\n' && buf[pos3]!='\0' && buf[pos3]!='#')
		pos3++;
	    /* one back and remove trailing whitespace */
	    do {
		pos3--;
	    } while (buf[pos3]==' ' || buf[pos3]=='\t');
	    if ((len=pos3-pos2+1)>0)  {
		if ( (value=(char*)calloc(1,len+1))==NULL )
		    return NULL;
		strncpy(value,&(buf[pos2]),len);
		break;
	    }
	    pos=pos3;
	}
	/* Skip till next line or end of buffer */
	while (buf[pos]!='\n' && buf[pos]!='\0')
	    pos++;
    } while (value==NULL && buf[pos]!='\0');

    return value;
}

int _nss_lcmapsd_parse_config(lcmapsd_opts_t *opts) {
    char *buf;
    char *strval;
    int rc,intval;

    rc=_nss_lcmapsd_read_conf_file(&buf);

    if ( (strval=_nss_lcmapsd_conf_value(buf, "LCMAPSD_URL")) != NULL)
	opts->lcmapsd_url=strval;
    else
	opts->lcmapsd_url=strdup(LCMAPSD_URL);

    if ( (strval=_nss_lcmapsd_conf_value(buf, "LCMAPSD_TIMEOUT")) != NULL &&
	sscanf(strval,"%d",&intval)==1 )
	opts->lcmapsd_timeout=intval;
    else
	opts->lcmapsd_timeout=LCMAPSD_TIMEOUT;
    free(strval);

    return 0;
}
