#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#define SPLITE_LOG_FILE	
#define PROPERTY_VALUE_MAX 	(2048)
#ifdef SPLITE_LOG_FILE
#define MAX_LOG_SIZE         	(128*1024*1024)
#else
#define MAX_LOG_SIZE         	(128*1024)
#endif
#define LOG_FILE		"rom.log"
int log_file_write(const char *args1, ...);

#define DEBUG

#ifdef DEBUG
#define debug(fmt, args...) log_file_write(fmt, ##args)
#else
#define debug(fmt, args...) do{}while(0)
#endif



