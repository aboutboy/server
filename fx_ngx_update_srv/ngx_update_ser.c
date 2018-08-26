#include <ngx_update.h>

#define CHECK_USR_PWD_FAILED "usrname or passwd is incorrect "
static int padding_and_send_ack(int fd, ack_t *ack, unsigned int pro, int result, char *data, int len)
{
	if (NULL == ack || pro < (unsigned int)0xf0000000) {
		return -1;
	}	

	ack->pro_num = pro;
	ack->result = result;
	ack->data_len = len;
	if (NULL != data && len > 0) {
		memcpy(ack->data, data, len);
		ack->len = sizeof(ack_t) + len;
	} else {
		ack->len = sizeof(ack_t);
	}

	if (send(fd, ack, ack->len, 0) < 0) {
		log_file_write("%s: send failed.", strerror(errno));
		return -1;
	}

	return 0;
}

static int check_usr_pwd(pro_head_t *h)
{
	if (NULL == h) {
		return -1;
	}

	if (h->data_len > 0) {
		usrname_passwd_t *usr_pwd = (usrname_passwd_t *)h->data;
		if (NULL == usr_pwd) {
			log_file_write("error: no usr pwd.\n");
			return -1;
		}

		if (0 != strncmp(usr_pwd->usrname, WIFI_USRNAME, strlen(WIFI_USRNAME)) || 
				0 != strncmp(usr_pwd->passwd, WIFI_PASSWD, strlen(WIFI_PASSWD))) {
			log_file_write("usrname or passwd is incorrect.");
			return -1;	
		}
	}
	log_file_write("usrname and passwd ok.");
	return 0;
}

static int handle_login_request(int fd, pro_head_t *h)
{
	ack_t *ack;
	int total_len;
	if (fd < 0 || NULL == h || h->pro_num != (unsigned int )LOGIN_REQ) {
		return -1;
	}

	if (check_usr_pwd(h) < 0) {
		total_len = sizeof(ack_t) + sizeof(CHECK_USR_PWD_FAILED);
		ack = calloc(1, total_len);
		if (NULL == ack) {
			log_file_write("%s: calloc failed.\n", strerror(errno));
			return -1;
		}

		if (padding_and_send_ack(fd, ack, LOGIN_ACK, -1, 
				CHECK_USR_PWD_FAILED, sizeof(CHECK_USR_PWD_FAILED)) < 0) {
			log_file_write("padding_and_send_ack() failed.\n");
			free(ack);
			return -1;
		}
	}
	
	total_len = sizeof(ack_t);
	ack = calloc(1, total_len);
	if (NULL ==  ack) {
		log_file_write("%s: calloc failed.\n", strerror(errno));
		return -1;
	}

	if (padding_and_send_ack(fd, ack, LOGIN_ACK, 0, NULL, 0) < 0) {
		log_file_write("padding_and_send_ack() failed.\n");
		free(ack);
		return -1;
	}

	free(ack);

	return 0;
}

#define		FX_K2P_VER_UPDATE_FILE "/home/zyg/fx_ngx_update_srv/k2p_conf/ver.txt"
#define		FX_K2_VER_UPDATE_FILE "/home/zyg/fx_ngx_update_srv/k2_conf/ver.txt"

static int read_ver_file(pro_head_t *h, char *buf, int len)
{
	FILE *fp;
	char line[VER_BUFFER_LEN] = {0};
	int found = 0;
	
	if (NULL == h || NULL == buf || len <= 0 || len > VER_BUFFER_LEN) {
		return -1;
	}

	if (1 == h->hd_type) {
		fp = fopen(FX_K2P_VER_UPDATE_FILE, "r");
	} else if (2 == h->hd_type) {
		fp = fopen(FX_K2_VER_UPDATE_FILE, "r");
	}	else {
		log_file_write("no found correspondence hard type.");
		return -1;
	}
	
	if (NULL == fp) {
		log_file_write("%s: fopen failed.\n", strerror(errno));
		return -1;
	}

	while(!feof(fp)) {
		if (fgets(line, VER_BUFFER_LEN, fp)) {
			if (0 == strncmp(h->data, line, strlen(line))) {
				break;
			}
		}
		memset(line, 0, VER_BUFFER_LEN);
	}
	
	//found next ver
	memset(buf, 0, len);
	if (fgets(buf, len, fp) && strlen(buf) > 1) {
		found = 1;
	}

	fclose(fp);
	
	return found;
}

static int handle_ver_update_request(int fd, pro_head_t *h)
{
	char buf[VER_BUFFER_LEN] = {0};
	ack_t *ack = NULL;
	int total_len, buf_len;

	if (fd < 0 || NULL == h || h->pro_num != (unsigned int)VER_UPDATE_REQ) {
		return -1;
	}

	if (h->data_len <= 0) {
		log_file_write("VER_UPDATE_REQ no data.");
		return -1;
	}

	if (1 == read_ver_file(h, buf, VER_BUFFER_LEN)) {
		log_file_write("found new ver:%s", buf);
		buf_len = strlen(buf);
		total_len = sizeof(ack_t) + buf_len;
		
		ack = calloc(1, total_len);
		if (NULL == ack) {
			log_file_write("%s: calloc failed.\n", strerror(errno));
			return -1;
		}

		if (padding_and_send_ack(fd, ack, VER_UPDATE_ACK, 1, buf, buf_len) < 0) {
			log_file_write("padding_and_send_ack() failed.\n");
			free(ack);
			return -1;
		}
	} else {
		log_file_write("no found new ver.\n");
		total_len = sizeof(ack_t);
		
		ack = calloc(1, total_len);
		if (NULL == ack) {
			log_file_write("%s: calloc failed.\n", strerror(errno));
			return -1;
		}

		if (padding_and_send_ack(fd, ack, VER_UPDATE_ACK, 0, NULL, 0) < 0) {
			log_file_write("padding_and_send_ack() failed.\n");
			free(ack);
			return -1;
		}
	}

	if (ack) free(ack);
	return 0;
}

#define FX_K2P_VER_FILE_DL_PATH "/home/zyg/fx_ngx_update_srv/k2p_conf/ver_file"
#define FX_K2_VER_FILE_DL_PATH "/home/zyg/fx_ngx_update_srv/k2_conf/ver_file"

int connect_new_ver_file_name(char *name, char *buf, int len, int type)
{
	int name_len;

	if (NULL == name || NULL == buf || 0 == len) {
		return -1;
	}
	
	memset(buf, 0, len);

	name_len = strlen(name);
	if (name_len > VER_BUFFER_LEN) {
		log_file_write("%s: file name too long. maybe not incorrect.\n", name);
		return -1;
	}

	if (1 == type) {
		if (len <= (name_len + sizeof(FX_K2P_VER_FILE_DL_PATH) + sizeof(TARGZ_FILE_SUFFIX))) {
			log_file_write("buf len is not enough.\n");
			return -1;
		}

		strncpy(buf, FX_K2P_VER_FILE_DL_PATH, sizeof(FX_K2P_VER_FILE_DL_PATH) - 1);
	} else if (2 == type) {
		if (len <= (name_len + sizeof(FX_K2_VER_FILE_DL_PATH) + sizeof(TARGZ_FILE_SUFFIX))) {
			log_file_write("buf len is not enough.\n");
			return -1;
		}

		strncpy(buf, FX_K2_VER_FILE_DL_PATH, sizeof(FX_K2_VER_FILE_DL_PATH) - 1);
	} else {
		log_file_write("the hardware type is incorrect.");
		return -1;
	}

	strncat(buf, "/", 1);
	strncat(buf, name, name_len);
	strncat(buf, TARGZ_FILE_SUFFIX, sizeof(TARGZ_FILE_SUFFIX) - 1);

	return 0;
}

int read_new_ver_file(char *buf, int len, char *filename, int offset)
{
	FILE *fp = NULL;
	int ret = 0;

	if (NULL == buf || 0 == len || NULL == filename || offset < 0) {
		return -1;
	}
	
	memset(buf, 0, len);
	fp = fopen(filename, "r");
	if (NULL == fp) {
		log_file_write("open file %s failed.", filename);
		return -1;
	}

	rewind(fp);
	
	if (fseek(fp, offset, SEEK_SET) < 0) {
		log_file_write("%s: fseek failed.", strerror(errno));
		fclose(fp);
		return -1;
	}

	if (!feof(fp)) {
		ret = read(fileno(fp), buf, len);
		if (ret < 0) {
			log_file_write("%s: read failed.", strerror(errno));
			fclose(fp);
			return -1;
		}

		if (0 == ret) {
			log_file_write("read file over.");
			fclose(fp);
			return 0;
		}

	}

	fclose(fp);
	return ret;
}

int padding_trans_file_content_struct(trans_file_content_t *content, char *filename, 
									int file_len, int offset, char *buf, int buf_len)
{
	int filename_len;
	if (NULL == content || NULL == filename || file_len <= 0 || 
			offset < 0 || buf_len <= 0 || NULL == buf) {
		return -1;
	}

	filename_len = strlen(filename);
	if (filename_len > FILE_NAME_MAX_LEN) {
		log_file_write("file name too long, maybe incorrect.\n");
		return -1;
	}

	strncpy(content->f_name, filename, filename_len);
	content->len = sizeof(trans_file_content_t);
	content->f_total_len	= file_len;
	content->f_offset		= offset;
	content->f_content_len  = buf_len;

	memcpy(content->f_content, buf, buf_len);
	return 0;
}

int get_file_size(const char *path)  
{  
	struct stat statbuff;  
	
	if (NULL == path) {
		return -1;
	}

	if (stat(path, &statbuff) < 0) { 
		log_file_write("%s: stat failed.", strerror(errno));
		return -1;  
	}   
	

	return statbuff.st_size; 
}

int get_file_name(char *path, char *filename, int namelen)
{
	char *p = NULL;
	int len;
	if (NULL == path || NULL == filename || namelen <= 0) {
		return -1;
	}

	memset(filename, 0, namelen);
	p = strrchr(path, '/');
	if (NULL == p) {
		log_file_write("found name failed.\n");
		return -1;
	}

	p++;
	len = strlen(p);
	if (len > namelen) {
		log_file_write("file name too long.\n");
		return -1;
	}

	strncpy(filename, p, len);
	
	return 0;
}

static int handle_ver_dl_request(int fd, pro_head_t *h)
{
	char send_file_path[PATH_MAX_LEN] = {0};
	char buf[PROPERTY_VALUE_MAX] = {0};
	char filename[FILE_NAME_MAX_LEN] = {0};
	int filesize, read_file_offset;
	file_ver_offset_t *ver = NULL;
	ack_t *ack = NULL;
	int content_len, read_len = 0, total_len;
	trans_file_content_t file_content_st = {0};

	if (fd < 0 || NULL == h || h->data_len <= 0) {
		return -1;
	}
	
	ver = (file_ver_offset_t *)h->data;
	if (NULL == ver) {
		log_file_write("no found ver info.\n");
		return -1;
	}

	if (connect_new_ver_file_name(ver->new_ver, send_file_path, sizeof(send_file_path), h->hd_type) < 0) {
		log_file_write("connect_new_ver_file_name() failed.\n");
		return -1;
	}

	// check file size
	filesize = get_file_size(send_file_path);
	if (filesize < 0) {
		log_file_write("get_file_size() failed.");
		return -1;
	}

	// get send file name
	if (get_file_name(send_file_path, filename, 
				FILE_NAME_MAX_LEN) < 0) {
		log_file_write("get_file_name() failed.");
		return -1;
	}

	content_len = sizeof(trans_file_content_t);
	total_len = sizeof(ack_t) + content_len;
	ack = calloc(1, total_len);
	if (NULL == ack) {
		log_file_write("%s: callocl failed.", strerror(errno));
		return -1;
	}

	for (read_file_offset = ver->offset; read_file_offset < filesize; read_file_offset += read_len) {
		
		read_len = read_new_ver_file(buf, sizeof(buf), send_file_path, read_file_offset);
		if (read_len < 0) {
			log_file_write("read_new_ver_file() failed.");
			free(ack);
			return -1;
		}
		
		if (0 == read_len) {
			log_file_write("maybe read file over.");
			break;
		}

		if (padding_trans_file_content_struct(&file_content_st, filename, filesize, read_file_offset, 
					buf, read_len) < 0) {
			log_file_write("padding_trans_file_content_struct() failed.");
			free(ack);
			return -1;
		}

		if (padding_and_send_ack(fd, ack, (unsigned int)VER_DL_ACK, 1, (char *)&file_content_st, content_len) < 0) {
			log_file_write("padding_and_send_ack() failed.");
			free(ack);
			return -1;
		}

		memset(buf, 0, PROPERTY_VALUE_MAX);
		memset(&file_content_st, 0, content_len);
		memset(ack, 0, total_len);
		//usleep(1000);
		log_file_write("get new ver file: %s, offset: %d, file size: %d, send len: %d", send_file_path, read_file_offset, filesize, read_len);
	}

	free(ack);
	
	if (filesize <= read_file_offset) {
		log_file_write("file transfer over.\n");
		ack = calloc(1, sizeof(ack_t));
		if (NULL == ack) {
			log_file_write("%s: calloc failed.\n", strerror(errno));
			return -1;
		}

		if (padding_and_send_ack(fd, ack, VER_DL_ACK, 0, NULL, 0) < 0) {
			log_file_write("padding_and_send_ack() failed.\n");
			free(ack);
			return -1;
		}

		free(ack);
	}

	return 0;
}
static void handle_request(int newfd)
{
	char buf[PROPERTY_VALUE_MAX] = {0};
	int ret, len, i;
	struct timeval timeout={7, 0};
	setsockopt(newfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval));

	for(i = 0; i < 3; i++) {
		memset(buf, 0, PROPERTY_VALUE_MAX);
		// set timeout
		len = recv(newfd, buf, sizeof(buf), 0);
		if (len < 0) {
			log_file_write("%s: recv failed.", strerror(errno));
			break;
		}

		if (len == 0) {
			log_file_write("maybe peer closed.");
			break;
		}
		
		pro_head_t *h = (pro_head_t *)buf;
		if (h->ver == PROTOL_VER) {
			switch(h->pro_num) {
				case (unsigned int)(LOGIN_REQ):
					ret = handle_login_request(newfd, h);
					if (ret < 0) {
						log_file_write("handle_iccid_login_request() failed.");
					}
					break;
				case (unsigned int)VER_UPDATE_REQ:
					ret = handle_ver_update_request(newfd, h);
					if (ret < 0) {
						log_file_write("handle_ver_update_request() failed.");
					}
					break;
				case (unsigned int)VER_DL_REQ:
					ret = handle_ver_dl_request(newfd, h);
					if (ret < 0) {
						log_file_write("handle_ver_dl_request() failed.");
					}
					break;
			}
		}
		if (ret < 0) {
			break;
		}
	}
}
static void handle_connect(int sockfd)
{
	int newfd;
	struct sockaddr_in c_addr;
	socklen_t in_len = sizeof(struct sockaddr_in);
	pid_t child_pid;
	while(1) {
		memset(&c_addr, 0, in_len);
		if((newfd = accept(sockfd, (struct sockaddr*)&c_addr, &in_len)) < 0) {
			if (errno == EINTR) {
				continue;
			}
			log_file_write("%s: accept failed.", strerror(errno));
			return;
		}
		log_file_write("====client: %s:%d====", inet_ntoa(c_addr.sin_addr), ntohs(c_addr.sin_port));
		child_pid = fork();
		if (0 == child_pid) {
			close(sockfd);
			handle_request(newfd);
			close(newfd);
			exit(0);
		}
		waitpid(child_pid, NULL, 0);
		close(newfd);
	}
}


int main(int argc, char *argv[])
{
	int sockfd;
	struct sockaddr_in s_addr;
	unsigned int port = 0, on, opt;
	
	log_file_write("=======begin record========\n");
	
	
	bzero(&s_addr, sizeof(s_addr));
	
	while ( -1 != (opt = getopt(argc, argv, "a:p:h"))) {
		switch (opt) {
			case 'a':
				s_addr.sin_addr.s_addr = inet_addr(optarg);
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf("Usage:\n");
				printf("\t %s [-a ip] [-p port]\n", argv[0]);
				return -1;
		}
	}
	
	if (0 == s_addr.sin_addr.s_addr) {
		s_addr.sin_addr.s_addr = inet_addr(SERV_IP);
	}
	if (0 == port) {
		port = SERV_PORT;
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		log_file_write("%s: socket failed.", strerror(errno));
		return -1;
	}

	// set SO_REUSEADDR
	on = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		log_file_write("%s: setsockopt failed.", strerror(errno));
		return -1;
	}
	
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(port);
	

	if ((bind(sockfd, (struct sockaddr*) &s_addr, sizeof(struct sockaddr))) < 0) {
		log_file_write("%s: bind failed.\n", strerror(errno));
		exit(errno);
	}
	
	if (listen(sockfd, 30) < 0) {
		log_file_write("%s: listen failed.\n", strerror(errno));
		exit(errno);
	}

	handle_connect(sockfd);

	close(sockfd);

	return 0;
}
