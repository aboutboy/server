/*************************************************************************
	> File Name: qm_wifi_update.h
	> Author: zyg
	> Mail: 20630196@qq.com 
	> Created Time: Fri Aug 19 18:39:49 2016
 ************************************************************************/

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/mount.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>

#define SERV_IP "115.28.82.25"
#define	SERV_PORT	25354	
#define WIFI_USRNAME	"test"
#define	WIFI_PASSWD	"12345678"
#define	FILE_NAME_MAX_LEN	(256)
#define PATH_MAX_LEN	(512)
#define	USR_PWD_MAX_LEN	(64)
#define	PROTOL_VER	1
#define PROPERTY_VALUE_MAX 1024
#define MAX_TRANS_LEN 1312 // qm_trans_file_content_t's len 1296, qm_ack_t's len 16
#define VER_BUFFER_LEN	32
#define	MAX_LOG_SIZE		(10*1024*1024)
#define	WIFI_UPDATE_LOG_FILE		"/mnt/sda1/data/sys_log/wifi_update.log"
#define	WIFI_UPDATE_SERVER_LOG_FILE		"/home/zyg/ngx_update_srv/logs/wifi_update_server.log"
#define TMP_FILE_SUFFIX ".tmp"
#define BAK_FILE_SUFFIX ".bak"
#define ORG_FILE_SUFFIX ".org"
#define TARGZ_FILE_SUFFIX ".tar.gz"
#define DECOMPRESS_TARGZ_CMD "tar -zxf %s -C %s"


typedef struct _qm_string_t {
	unsigned int len;
	char *data;
}qm_string_t;

typedef struct {
	char usrname[USR_PWD_MAX_LEN];
	char passwd[USR_PWD_MAX_LEN];
}usrname_passwd_t;

typedef struct {
	unsigned int offset;
	char new_ver[VER_BUFFER_LEN];
}file_ver_offset_t;

typedef struct {
	unsigned int len;
	unsigned int ver;
	unsigned int pro_num;
	unsigned int hd_type; // 1:fxk2p, 2:fxk2,
	unsigned int data_len;
	char data[0];
}pro_head_t;

typedef struct {
	unsigned int pro_num;
	unsigned int len;
	int result;		// >0:success, <0:fail
	unsigned int data_len;
	char data[0];
}ack_t;


typedef struct {
	unsigned int len;
	char f_name[FILE_NAME_MAX_LEN];
	unsigned int f_total_len;
	unsigned int f_offset;
	unsigned int f_content_len;

	char f_content[PROPERTY_VALUE_MAX];
}trans_file_content_t;

enum {
	LOGIN_REQ 	= 0x20000001,
	VER_UPDATE_REQ,
	VER_DL_REQ,
}req_pro_num;

enum {
	LOGIN_ACK = 0xf0000001,
	VER_UPDATE_ACK,
	VER_DL_ACK,
}ack_pro_num;

int check_update_and_download_sys(void);
int log_file_write(const char *args1, ...);
int perform_update(void);
int download_update_file(int fd);
pro_head_t *padding_pro_req(int pro, void *data, int len);
int cat_file_path(char *buf, unsigned int len, char *path, char *filename);
int recv_ack_general(int fd, unsigned int pro, char *filename);
int check_files_name_suffix(char *path, char *ends);
