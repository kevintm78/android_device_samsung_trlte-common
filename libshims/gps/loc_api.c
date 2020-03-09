#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>

#define TS_PRINTF(format, x...)                                \
{                                                              \
  struct timeval tv;                                           \
  struct timezone tz;                                          \
  int hh, mm, ss;                                              \
  gettimeofday(&tv, &tz);                                      \
  hh = tv.tv_sec/3600%24;                                      \
  mm = (tv.tv_sec%3600)/60;                                    \
  ss = tv.tv_sec%60;                                           \
  fprintf(stdout,"%02d:%02d:%02d.%06ld]" format "\n", hh, mm, ss, tv.tv_usec,##x);    \
}

//#define IF_LOC_LOGV if((loc_logger.DEBUG_LEVEL >= 5) && (loc_logger.DEBUG_LEVEL <= 5))
#define LOC_LOGGER_DEBUG_LEVEL (5)
#define IF_LOC_LOGV if(LOC_LOGGER_DEBUG_LEVEL == 5)
#define ALOGV(format, x...) TS_PRINTF("V/%s (%d): " format , "LocSvc_engM", getpid(), ##x)
#define LOC_LOGV(...) IF_LOC_LOGV { ALOGV(__VA_ARGS__); }


inline void locallog() {
    LOC_LOGV("LocEngReportStatus");
}



/*===========================================================================
FUNCTION    loc_eng_nmea_put_checksum
DESCRIPTION
   Generate NMEA sentences generated based on position report
DEPENDENCIES
   NONE
RETURN VALUE
   Total length of the nmea sentence
SIDE EFFECTS
   N/A
===========================================================================*/
int _Z25loc_eng_nmea_put_checksumPci(char *pNmea, int maxSize)
{
    u_int8_t checksum = 0;
    int length = 0;

    pNmea++; //skip the $
    while (*pNmea != '\0')
    {
        checksum ^= *pNmea++;
        length++;
    }

    // length now contains nmea sentence string length not including $ sign.
    int checksumLength = snprintf(pNmea,(maxSize-length-1),"*%02X\r\n", checksum);

    // total length of nmea sentence is length of nmea sentence inc $ sign plus
    // length of checksum (+1 is to cover the $ character in the length).
    return (length + checksumLength + 1);
}



#include <sys/types.h>


// original function name: _ZNK16LocEngReportNmea4procEv
// elfhash generated with same hash:_ZNK16LocEngReportNmea4procFf
// https://github.com/18446744073709551615/reDroid/blob/master/hosttools/elfhash.c


//extern "C" {
//  ssize_t _ZNK16LocEngReportNmea4procFf(void *thiz, void* locEng, const char* data, int len ) ;

  ssize_t _ZNK16LocEngReportNmea4procEv(void *thiz, void* locEng, const char* data, int len ) {
    static ssize_t (*fun)(void *, void*, const char*, int )=0;
    if( fun==0) {
      void *handle ;
      char *error ;
      handle = dlopen ("/system/vendor/lib/libloc_eng.so", RTLD_LAZY);
      if( ! handle) exit(1) ;
      fun = dlsym( handle, "_ZNK16LocEngReportNmea4procEv" ) ;
      if ((error = dlerror()) != NULL)  {
	//            fputs(error, stderr);
            exit(1);
        }
    }
    return (*fun)(thiz, locEng, data, len+1 ) ;
  }
//}

#if 0

//        case LOC_ENG_MSG_REPORT_NMEA:
LocEngReportNmea::LocEngReportNmea(void* locEng,
                                   const char* data, int len) :
    LocMsg(), mLocEng(locEng), mNmea(new char[len+1]), mLen(len)
{
    strlcpy(mNmea, data, len+1);
    locallog();
}

LocEngReportNmea * __thiscall
LocEngReportNmea(LocEngReportNmea *this,void *locEng,char *data,int len)

{
  void *__dest;
  int iVar1;

  *(void **)(this + 4) = locEng;
  *(undefined4 *)this = 0x33470;
  iVar1 = len;
  __dest = operator.new[](len);
  *(void **)(this + 8) = __dest;
  *(int *)(this + 0xc) = len;
  memcpy(__dest,data,len);
  if (loc_logger == 5) {
    __android_log_print(6,"LocSvc_eng","V/LocEngReportNmea",&loc_logger,iVar1);
  }
  return this;
}

#endif
