/**
 * Copyright 2019-2020 DigitalOcean Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PROM_LOG_H
#define PROM_LOG_H

#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>


#include <stdio.h>
#include <stdint.h>
#include <time.h>


static inline uint8_t get_current_log_prio() { return LOG_DEBUG; }

#define STR_HELPER(__x) #__x
#define STR(__x) STR_HELPER(__x)
#define __PLACE__ __FILE__ ":" STR(__LINE__)


#define LOG_TS_FORMAT "%d-%02d-%02dT%02d:%02d:%02d.%03d%+.02ld:%02d"


#ifndef DISABLE_LOGCOLOR

#define LOGCOLOR_SUFFIX "\033[0m"

#define PRIO_LOG_EMERG_PREFIX   "\033[31;4;5m"
#define PRIO_LOG_ALERT_PREFIX   "\033[31m"
#define PRIO_LOG_CRIT_PREFIX    "\033[31;2m"
#define PRIO_LOG_ERR_PREFIX     "\033[31;1m"
#define PRIO_LOG_WARNING_PREFIX "\033[33;1m"
#define PRIO_LOG_NOTICE_PREFIX  "\033[32;1m"
#define PRIO_LOG_INFO_PREFIX    "\033[39m"
#define PRIO_LOG_DEBUG_PREFIX   "\033[37;2m"

#else /* DISABLE_LOGCOLOR */

#define LOGCOLOR_SUFFIX ""

#define PRIO_LOG_EMERG_PREFIX    ""
#define PRIO_LOG_ALERT_PREFIX    ""
#define PRIO_LOG_CRIT_PREFIX    ""
#define PRIO_LOG_ERR_PREFIX        ""
#define PRIO_LOG_WARNING_PREFIX    ""
#define PRIO_LOG_NOTICE_PREFIX    ""
#define PRIO_LOG_INFO_PREFIX    ""
#define PRIO_LOG_DEBUG_PREFIX    ""

#endif /* DISABLE_LOGCOLOR */

static const char __attribute__((unused)) *__prio_names[] = {
    PRIO_LOG_EMERG_PREFIX   "EMERG" LOGCOLOR_SUFFIX "   ",
    PRIO_LOG_ALERT_PREFIX   "ALERT" LOGCOLOR_SUFFIX "   ",
    PRIO_LOG_CRIT_PREFIX    "CRIT" LOGCOLOR_SUFFIX "    ",
    PRIO_LOG_ERR_PREFIX     "ERR" LOGCOLOR_SUFFIX "     ",
    PRIO_LOG_WARNING_PREFIX "WARNING" LOGCOLOR_SUFFIX " ",
    PRIO_LOG_NOTICE_PREFIX  "NOTICE" LOGCOLOR_SUFFIX "  ",
    PRIO_LOG_INFO_PREFIX    "INFO" LOGCOLOR_SUFFIX "    ",
    PRIO_LOG_DEBUG_PREFIX   "DEBUG" LOGCOLOR_SUFFIX "   ",
};



#define _LOGJF(...) #__VA_ARGS__
#define LOGJF(...) LOGCOLOR_SUFFIX " " _LOGJF({__VA_ARGS__ })

#ifndef DISABLE_LOGCOLOR

#define LOGJFC(__n) \033[36;1m __n\033[0m : \033[33;1m"%s[%s:%d]"\033[0m

#define LOGJFS(__n) \033[36;1m __n\033[0m : \033[33;1m"%s"\033[0m
#define LOGJFP(__n) \033[36;1m __n\033[0m : \033[32;1m%p\033[0m
#define LOGJFD(__n) \033[36;1m __n\033[0m : \033[32;1m%d\033[0m
#define LOGJFL(__n) \033[36;1m __n\033[0m : \033[32;1m%ld\033[0m
#define LOGJFF(__n) \033[36;1m __n\033[0m : \033[32;1m%f\033[0m

#else /* DISABLE_LOGCOLOR */

#define LOGJFC(__n) __n : "%s[%s:%d]"

#define LOGJFS(__n) __n : "%s"
#define LOGJFP(__n) __n : %p
#define LOGJFD(__n) __n : %d
#define LOGJFL(__n) __n : %ld
#define LOGJFF(__n) __n : %f

#endif /* DISABLE_LOGCOLOR */


#define __LOGMSG(__printf, __prio, __fmt, ...)                              \
    do {                                                                    \
        if (get_current_log_prio() >= __prio) {                             \
            __printf(                                                       \
                __prio,                                                     \
                "%s"        /* log priority */                              \
                "TID%-8x"   /* thread ID */                                 \
                "%-20s"     /* place: 12(file) + 1(:) + 5(line) + 2(pad); */\
                "%-20s "    /* function name */                             \
                __fmt "\n", /* format for debug info */                     \
                __prio_names[LOG_PRI(__prio)],                              \
                0xDEADBEEF,                                                 \
                __PLACE__,                                                  \
                __func__,                                                   \
                ##__VA_ARGS__);                                             \
        }                                                                   \
    } while (0)

#define LOGMSG(__prio, __fmt, ...)                                          \
    __LOGMSG(logmsg, __prio, __fmt, ##__VA_ARGS__)

#define __LOGSTDERR(__prio, __fmt, ...)                                     \
    fprintf(stderr, __fmt, ##__VA_ARGS__)
#define LOGSTDERR(__prio, __fmt, ...)                                       \
    __LOGMSG(__LOGSTDERR, __prio, __fmt, ##__VA_ARGS__)

#define __LOGSTDOUT(__prio, __fmt, ...)                                     \
    fprintf(stdout, __fmt, ##__VA_ARGS__)
#define LOGSTDOUT(__prio, __fmt, ...)                                       \
    __LOGMSG(__LOGSTDOUT, __prio, __fmt, ##__VA_ARGS__)

#define LOGEMERG(__fmt, ...)    LOGMSG(LOG_EMERG,    __fmt, ##__VA_ARGS__)
#define LOGALERT(__fmt, ...)    LOGMSG(LOG_ALERT,    __fmt, ##__VA_ARGS__)
#define LOGCRIT(__fmt, ...)        LOGMSG(LOG_CRIT,    __fmt, ##__VA_ARGS__)
#define LOGERR(__fmt, ...)        LOGMSG(LOG_ERR,        __fmt, ##__VA_ARGS__)
#define LOGWARNING(__fmt, ...)    LOGMSG(LOG_WARNING,    __fmt, ##__VA_ARGS__)
#ifndef DISABLE_LOGNOTICE
# define LOGNOTICE(__fmt, ...)    LOGMSG(LOG_NOTICE,    __fmt, ##__VA_ARGS__)
#else    /*    DISABLE_LOGNOTICE    */
# define LOGNOTICE(__fmt, ...)
#endif    /*    DISABLE_LOGNOTICE    */
#ifndef DISABLE_LOGINFO
# define LOGINFO(__fmt, ...)    LOGMSG(LOG_INFO,    __fmt, ##__VA_ARGS__)
#else    /*    DISABLE_LOGINFO    */
# define LOGINFO(__fmt, ...)
#endif    /*    DISABLE_LOGINFO    */
#ifndef DISABLE_LOGDEBUG
# define LOGDEBUG(__fmt, ...)    LOGMSG(LOG_DEBUG,    __fmt, ##__VA_ARGS__)
#else    /*    DISABLE_LOGDEBUG    */
# define LOGDEBUG(__fmt, ...)
#endif    /*    DISABLE_LOGDEBUG    */


static inline char *timestamp(char *buf, size_t buf_size)
{
	struct tm tm;
	struct timeval now_tv;
	int ms, mask, m_offset = 0;
	
	gettimeofday(&now_tv, NULL);
	ms = (int)(now_tv.tv_usec / 1000);
	localtime_r(&(now_tv.tv_sec), &tm);
	if (tm.tm_gmtoff % 3600 != 0) {	/*minute offset calc*/
		m_offset = (tm.tm_gmtoff/60)%60;	/*abs() free abs*/
		mask = m_offset >> 31;
		m_offset = (m_offset ^ mask) - mask;
	}

	/* Add clear line only if stderr is going to console */
	// if (isatty(fileno(f)))
	// 	fprintf(f, "\33[2K\r");
	snprintf(buf, buf_size, LOG_TS_FORMAT "  ",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,/*day*/
		tm.tm_hour, tm.tm_min, tm.tm_sec, ms,
		tm.tm_gmtoff/3600, m_offset);

    return buf;
}

#ifdef PROM_LOG_ENABLE
#define PROM_LOG(msg) printf("%s %s %s %s %d %s\n", __DATE__, __TIME__, __FILE__, __FUNCTION__, __LINE__, msg);
#else
// #define PROM_LOG(msg)
#define PROM_LOG(msg) do { char buf[64]; LOGSTDOUT(LOG_INFO, "%s%s", timestamp(buf, sizeof(buf)), msg); } while(0)
#endif  // PROM_LOG_ENABLE

#endif  // PROM_LOG_H
