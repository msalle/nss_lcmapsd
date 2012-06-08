#include <nss.h>

#include <pwd.h>
#include <errno.h>

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#define LCMAPSD_URL	"http://localhost:8008/lcmaps/mapping/rest"
#define LCMAPSD_TIMEOUT	3L

/* Used as buffer space by _curl_memwrite */
struct MemoryStruct {
    char *memory;
    size_t size;
};

/**
 * see cURL getinmemory.c example
 */
static size_t
_curl_memwrite(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL)
	return 0;

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

/**
 * Parses memory as lcmapsd json. Looks for a valid uid.
 * \return 1 when uid is found, otherwise 0
 */
static int _lcmapsd_parse_json(char *memory, uid_t *uid)    {
    char *pos=memory;

    if ( (pos=strstr(pos,"\"posix\""))!=NULL &&
	 (pos=strstr(pos,"{"))!=NULL &&
	 (pos=strstr(pos,"\"uid\""))!=NULL &&
	 (pos=strstr(pos,"{"))!=NULL &&
	 (pos=strstr(pos,"\"id\""))!=NULL &&
	 (pos=strstr(pos,":"))!=NULL &&
	 sscanf(pos+1,"%d",uid)==1)
	return 1;
    else
	return 0;
}

/**
 * Does a callout to a lcmapsd, currently hardcoded to localhost for given name
 * \param name input DN
 * \param uid resulting uid
 * \return nss_status
 */ 
static enum nss_status
_lcmapsd_curl(const char *name, uid_t *uid)	{
    CURL *curl_handle;
    struct MemoryStruct chunk;
    char *base_url=LCMAPSD_URL "?format=json&subjectdn=";
    char *lcmapsd_url=NULL,*name_encoded=NULL;
    int rc,len=strlen(base_url);
    long httpresp;

    /* Initialize size of chunk */
    chunk.size=0;

    /* init the curl session */
    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();

    /* Do all memory operations, including conversion of name into url encoded
     * name */
    if ( (chunk.memory=(char*)malloc(1)) == NULL ||
         (name_encoded=curl_easy_escape(curl_handle, name, 0)) == NULL ) {
	rc=NSS_STATUS_TRYAGAIN;
	goto _curl_cleanup;
    }
    len+=strlen(name_encoded)+1;
    if ( (lcmapsd_url=(char*)malloc(len)) == NULL)  {
	rc=NSS_STATUS_TRYAGAIN;
	goto _curl_cleanup;
    }

    /* Create the full url, we know it fits as we prepared the length */
    snprintf(lcmapsd_url,len,"%s%s",base_url,name_encoded);

    /* Set curl options */
    curl_easy_setopt(curl_handle, CURLOPT_URL, lcmapsd_url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, _curl_memwrite);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    /* Timeout */
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, LCMAPSD_TIMEOUT);

    /* Do lookup */
    curl_easy_perform(curl_handle);
    curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &httpresp);

    /* cleanup curl stuff */
    curl_easy_cleanup(curl_handle);

    /* Did we receive a proper answer? */
    if (httpresp==200)	{
	if (chunk.size>0 && _lcmapsd_parse_json(chunk.memory, uid) )
	    rc=NSS_STATUS_SUCCESS;
	else
	    /* We got a 200, should have valid entry, set to try again */
	    rc=NSS_STATUS_TRYAGAIN;
	goto _curl_cleanup;
    }

    /* Parse the error */
    switch (httpresp) {
	case 403:
	    rc=NSS_STATUS_NOTFOUND;
	    goto _curl_cleanup;
	case 0:
	default:
	    rc=NSS_STATUS_UNAVAIL;
	    goto _curl_cleanup;
    }

_curl_cleanup:
    /* Cleanup memory */
    if (chunk.memory)	free(chunk.memory);
    if (name_encoded)	free(name_encoded);
    if (lcmapsd_url)	free(lcmapsd_url);

    /* we're done with libcurl, so clean it up */
    curl_global_cleanup();

    return rc;
}

/**
 * Actual nss lookup function trying to do a mapping via a lcmapsd
 */
enum nss_status
_nss_lcmapsd_getpwnam_r (const char *name, struct passwd *result, char *buffer,
                       size_t buflen, int *errnop)  {

    struct passwd *respointer=NULL;
    enum nss_status rc;
    uid_t uid;

    if ( (rc=_lcmapsd_curl(name,&uid)==NSS_STATUS_SUCCESS) )	{
	/* We got a valid result, now get the pw information for it */
	if (getpwuid_r(uid, result, buffer, buflen, &respointer)==0)
	    rc=NSS_STATUS_SUCCESS;
	else {
	    switch (errno)  {
		case 0:
		case ENOENT:
		case ESRCH:
		case EBADF:
		case EPERM:
		    rc=NSS_STATUS_NOTFOUND;
		    break;
		case EINTR:	/* signal */
		case EIO:	/* I/O */
		case EMFILE:	/* open max in calling process */
		case ENFILE:	/* open max in system */
		case ENOMEM:	/* insuff mem for passwd */
		    rc=NSS_STATUS_TRYAGAIN;
		    break;
		case ERANGE:
		    *errnop=ERANGE;
		    rc=NSS_STATUS_TRYAGAIN;
		    break;
		default: /* Unknown error: give up */
		    rc=NSS_STATUS_UNAVAIL;
		    break;
	    }
	}
    }
    return rc;
}

#ifdef MAKE_A_OUT
/**
 * Test main function, to check whether a valid uid can be obtained via the
 * lcmapsd
 */
int main(int argc, char *argv[])	{
    uid_t uid;
    int rc;
    char *dn;

    if (argc<2)    {
	fprintf(stderr,"Usage: %s <DN>\n",argv[0]);
	return 1;
    }
    dn=argv[1];
    rc=_lcmapsd_curl(dn,&uid);

    switch(rc)	{
	case NSS_STATUS_SUCCESS:
	    printf("uid=%d\n",uid); /* Only in this case valid */
	    printf("NSS_STATUS_SUCCESS\n");
	    break;
	case NSS_STATUS_TRYAGAIN:
	    printf("NSS_STATUS_TRYAGAIN\n");
	    break;
	case NSS_STATUS_UNAVAIL:
	    printf("NSS_STATUS_UNAVAIL\n");
	    break;
	case NSS_STATUS_NOTFOUND:
	    printf("NSS_STATUS_NOTFOUND\n");
	    break;
	case NSS_STATUS_RETURN:
	    printf("NSS_STATUS_RETURN\n");
	    break;
	default:
	    printf("rc=%d\n",rc);
	    break;
    }
    return 0;
}
#endif
