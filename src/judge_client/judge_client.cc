// File:   judge_client.cc
// Author: sempr
// refacted by zhblue
/*
 * Copyright 2008 sempr <iamsempr@gmail.com>
 *
 * Refacted and modified by zhblue<newsclan@gmail.com>
 * Bug report email newsclan@gmail.com
 *
 *
 * This file is part of HUSTOJ.
 *
 * HUSTOJ is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * HUSTOJ is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with HUSTOJ. if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/signal.h>
//#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include <assert.h>
#include "okcalls.h"

#define IGNORE_ESOL //ignore the ending space char of lines while comparing
#define STD_MB 1048576LL
#define STD_T_LIM 2
#define STD_F_LIM (STD_MB << 5) //default file size limit 32m ,2^5=32
#define STD_M_LIM (STD_MB << 7) //default memory limit 128m ,2^7=128
#define BUFFER_SIZE 5120		//default size of char buffer 5120 bytes

#define OJ_WT0 0
#define OJ_WT1 1
#define OJ_CI 2
#define OJ_RI 3
#define OJ_AC 4
#define OJ_PE 5
#define OJ_WA 6
#define OJ_TL 7
#define OJ_ML 8
#define OJ_OL 9
#define OJ_RE 10
#define OJ_CE 11
#define OJ_CO 12
#define OJ_TR 13
#define OJ_JF 14 //判题失败
/*copy from ZOJ
 http://code.google.com/p/zoj/source/browse/trunk/judge_client/client/tracer.cc?spec=svn367&r=367#39
 */
#ifdef __arm__
struct user_regs_struct{
        uint64_t uregs[38];
};

#define ARM_r7          uregs[7]
#define ARM_ORIG_r0     uregs[17]

#define REG_SYSCALL ARM_r7

#endif

#ifdef __mips__
typedef unsigned long long uint64_t;
struct user_regs_struct {
	uint64_t uregs[38];
};


#define REG_V0 2
#define REG_A0 4

#define mips_REG_V0 uregs[REG_V0]
#define REG_SYSCALL mips_REG_V0

#endif

#ifdef __i386
#define REG_SYSCALL orig_eax
#define REG_RET eax
#define REG_ARG0 ebx
#define REG_ARG1 ecx
#endif

#ifdef __x86_64__
#define REG_SYSCALL orig_rax
#define REG_RET rax
#define REG_ARG0 rdi
#define REG_ARG1 rsi

#endif

static int DEBUG = 0;
static char host_name[BUFFER_SIZE];
static char user_name[BUFFER_SIZE];
static char password[BUFFER_SIZE];
static char db_name[BUFFER_SIZE];
static char oj_home[BUFFER_SIZE];
static char data_list[BUFFER_SIZE][BUFFER_SIZE];
static int data_list_len = 0;

static char judge_name[BUFFER_SIZE];

static int port_number;
static int max_running;
static int sleep_time;
static int java_time_bonus = 5;
static int java_memory_bonus = 512;
static char java_xms[BUFFER_SIZE];
static char java_xmx[BUFFER_SIZE];
static int full_diff = 0;

static double cpu_compensation = 1.0;

static int shm_run = 0;

static char record_call = 0;
static int use_ptrace = 1;
static int compile_chroot = 1;
static const char *tbname = "status";
//static int sleep_tmp;

static int py2=1; // caution: py2=1 means default using py3

#define ZOJ_COM


MYSQL *conn;


static char lang_ext[19][8] = {"c", "cc", "pas", "java", "rb", "sh", "py",
                               "php", "pl", "cs", "m", "bas", "scm", "c", "cc", "lua", "js", "go","sql"
                              };
//static char buf[BUFFER_SIZE];
int data_list_has(char *file) {
	for (int i = 0; i < data_list_len; i++) {
		if (strcmp(data_list[i], file) == 0)
			return 1;
	}
	return 0;
}
int data_list_add(char *file) {
	if (data_list_len < BUFFER_SIZE - 1) {
		strcpy(data_list[data_list_len], file);
		data_list_len++;
		return 0;
	} else {
		return 1;
	}
}
long get_file_size(const char *filename) {
	struct stat f_stat;

	if (stat(filename, &f_stat) == -1) {
		return 0;
	}

	return (long)f_stat.st_size;
}

void write_log(const char *_fmt, ...) {
	va_list ap;
	char fmt[4096];
	strncpy(fmt, _fmt, 4096);
	char buffer[4096];
	//      time_t          t = time(NULL);
	//int l;
	sprintf(buffer, "%s/log/client.log", oj_home);
	FILE *fp = fopen(buffer, "ae+");
	if (fp == NULL) {
		fprintf(stderr, "openfile error!\n");
		system("pwd");
	}
	va_start(ap, _fmt);
	//l =
	vsprintf(buffer, fmt, ap);
	fprintf(fp, "%s\n", buffer);
	if (DEBUG)
		printf("%s\n", buffer);
	va_end(ap);
	fclose(fp);
}
int execute_cmd(const char *fmt, ...) {
	char cmd[BUFFER_SIZE];

	int ret = 0;
	va_list ap;

	va_start(ap, fmt);
	vsprintf(cmd, fmt, ap);
	if (DEBUG)
		printf("%s\n", cmd);
	ret = system(cmd);
	va_end(ap);
	return ret;
}

const int call_array_size = 512;
unsigned int call_id = 0;
unsigned int call_counter[call_array_size] = {0};
static char LANG_NAME[BUFFER_SIZE];
void init_syscalls_limits(int lang) {
	int i;
	memset(call_counter, 0, sizeof(call_counter));
	if (DEBUG)
		write_log("init_call_counter:%d", lang);
	if (record_call) {
		// recording for debuging
		for (i = 0; i < call_array_size; i++) {
			call_counter[i] = 0;
		}
	} else if (lang <= 1 || lang == 13 || lang == 14) {
		// C & C++
		for (i = 0; i == 0 || LANG_CV[i]; i++) {
			call_counter[LANG_CV[i]] = HOJ_MAX_LIMIT;
		}
	} else if (lang == 2) {
		// Pascal
		for (i = 0; i == 0 || LANG_PV[i]; i++)
			call_counter[LANG_PV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 3) {
		// Java
		for (i = 0; i == 0 || LANG_JV[i]; i++)
			call_counter[LANG_JV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 4) {
		// Ruby
		for (i = 0; i == 0 || LANG_RV[i]; i++)
			call_counter[LANG_RV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 5) {
		// Bash
		for (i = 0; i == 0 || LANG_BV[i]; i++)
			call_counter[LANG_BV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 6) {
		// Python
		for (i = 0; i == 0 || LANG_YV[i]; i++)
			call_counter[LANG_YV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 7) {
		// php
		for (i = 0; i == 0 || LANG_PHV[i]; i++)
			call_counter[LANG_PHV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 8) {
		// perl
		for (i = 0; i == 0 || LANG_PLV[i]; i++)
			call_counter[LANG_PLV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 9) {
		// mono c#
		for (i = 0; i == 0 || LANG_CSV[i]; i++)
			call_counter[LANG_CSV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 10) {
		//objective c
		for (i = 0; i == 0 || LANG_OV[i]; i++)
			call_counter[LANG_OV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 11) {
		//free basic
		for (i = 0; i == 0 || LANG_BASICV[i]; i++)
			call_counter[LANG_BASICV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 12) {
		//scheme guile
		for (i = 0; i == 0 || LANG_SV[i]; i++)
			call_counter[LANG_SV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 15) {
		//lua
		for (i = 0; i == 0 || LANG_LUAV[i]; i++)
			call_counter[LANG_LUAV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 16) {
		//nodejs
		for (i = 0; i == 0 || LANG_JSV[i]; i++)
			call_counter[LANG_JSV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 17) {
		//go
		for (i = 0; i == 0 || LANG_GOV[i]; i++)
			call_counter[LANG_GOV[i]] = HOJ_MAX_LIMIT;
	} else if (lang == 18) {
		//go
		for (i = 0; i == 0 || LANG_SQLV[i]; i++)
			call_counter[LANG_SQLV[i]] = HOJ_MAX_LIMIT;
	}
}

int after_equal(char *c) {
	int i = 0;
	for (; c[i] != '\0' && c[i] != '='; i++)
		;
	return ++i;
}
void trim(char *c) {
	char buf[BUFFER_SIZE];
	char *start, *end;
	strcpy(buf, c);
	start = buf;
	while (isspace(*start))
		start++;
	end = start;
	while (!isspace(*end))
		end++;
	*end = '\0';
	strcpy(c, start);
}
bool read_buf(char *buf, const char *key, char *value) {
	if (strncmp(buf, key, strlen(key)) == 0) {
		strcpy(value, buf + after_equal(buf));
		trim(value);
		if (DEBUG)
			printf("%s\n", value);
		return 1;
	}
	return 0;
}
void read_double(char *buf, const char *key, double *value) {
	char buf2[BUFFER_SIZE];
	if (read_buf(buf, key, buf2))
		sscanf(buf2, "%lf", value);
}

void read_int(char *buf, const char *key, int *value) {
	char buf2[BUFFER_SIZE];
	if (read_buf(buf, key, buf2))
		sscanf(buf2, "%d", value);
}

FILE *read_cmd_output(const char *fmt, ...) {
	char cmd[BUFFER_SIZE];

	FILE *ret = NULL;
	va_list ap;

	va_start(ap, fmt);
	vsprintf(cmd, fmt, ap);
	va_end(ap);
	if (DEBUG)
		printf("%s\n", cmd);
	ret = popen(cmd, "r");

	return ret;
}
// read the configue file
void init_mysql_conf() {
	FILE *fp = NULL;
	char buf[BUFFER_SIZE];
	host_name[0] = 0;
	user_name[0] = 0;
	password[0] = 0;
	judge_name[0] = 0;
	db_name[0] = 0;
	port_number = 3306;
	max_running = 3;
	sleep_time = 3;
	strcpy(java_xms, "-Xms32m");
	strcpy(java_xmx, "-Xmx256m");
	sprintf(buf, "%s/etc/judge.conf", oj_home);
	fp = fopen("./etc/judge.conf", "re");
	if (fp != NULL) {
		while (fgets(buf, BUFFER_SIZE - 1, fp)) {
			read_buf(buf, "OJ_HOST_NAME", host_name);
			read_buf(buf, "OJ_USER_NAME", user_name);
			read_buf(buf, "OJ_PASSWORD", password);
			read_buf(buf, "OJ_DB_NAME", db_name);
			read_int(buf, "OJ_PORT_NUMBER", &port_number);

			read_buf(buf, "OJ_JUDGE_NAME", judge_name);

			read_int(buf, "OJ_JAVA_TIME_BONUS", &java_time_bonus);
			read_int(buf, "OJ_JAVA_MEMORY_BONUS", &java_memory_bonus);
			read_buf(buf, "OJ_JAVA_XMS", java_xms);
			read_buf(buf, "OJ_JAVA_XMX", java_xmx);
			read_int(buf, "OJ_FULL_DIFF", &full_diff);
			read_int(buf, "OJ_SHM_RUN", &shm_run);
			read_int(buf, "OJ_USE_PTRACE", &use_ptrace);
			read_int(buf, "OJ_COMPILE_CHROOT", &compile_chroot);
			read_double(buf, "OJ_CPU_COMPENSATION", &cpu_compensation);
		}
		//fclose(fp);
	}
//	fclose(fp);

}

int isInFile(const char fname[]) {
	int l = strlen(fname);
	if (l <= 3 || strcmp(fname + l - 3, ".in") != 0)
		return 0;
	else
		return l - 3;
}

void find_next_nonspace(int &c1, int &c2, FILE *&f1, FILE *&f2, int &ret) {
	// Find the next non-space character or \n.
	while ((isspace(c1)) || (isspace(c2))) {
		if (c1 != c2) {
			if (c2 == EOF) {
				do {
					c1 = fgetc(f1);
				} while (isspace(c1));
				continue;
			} else if (c1 == EOF) {
				do {
					c2 = fgetc(f2);
				} while (isspace(c2));
				continue;
//#ifdef IGNORE_ESOL
			} else if (isspace(c1) && isspace(c2)) {
				while (c2 == '\n' && isspace(c1) && c1 != '\n')
					c1 = fgetc(f1);
				while (c1 == '\n' && isspace(c2) && c2 != '\n')
					c2 = fgetc(f2);

//#else
			} else if ((c1 == '\r' && c2 == '\n')) {
				c1 = fgetc(f1);
			} else if ((c2 == '\r' && c1 == '\n')) {
				c2 = fgetc(f2);
//#endif
			} else {
				if (DEBUG)
					printf("%d=%c\t%d=%c", c1, c1, c2, c2);
				;
				ret = OJ_PE;
			}
		}
		if (isspace(c1)) {
			c1 = fgetc(f1);
		}
		if (isspace(c2)) {
			c2 = fgetc(f2);
		}
	}
}

/***
 int compare_diff(const char *file1,const char *file2){
 char diff[1024];
 sprintf(diff,"diff -q -B -b -w --strip-trailing-cr %s %s",file1,file2);
 int d=system(diff);
 if (d) return OJ_WA;
 sprintf(diff,"diff -q -B --strip-trailing-cr %s %s",file1,file2);
 int p=system(diff);
 if (p) return OJ_PE;
 else return OJ_AC;

 }
 */
const char *getFileNameFromPath(const char *path) {
	for (int i = strlen(path); i >= 0; i--) {
		if (path[i] == '/')
			return &path[i + 1];
	}
	return path;
}

//void make_diff_out_full(FILE *f1, FILE *f2, int c1, int c2, const char *path) {
//
//	execute_cmd("echo '========[%s]========='>>diff.out", getFileNameFromPath(path));
//	execute_cmd("echo '------test in top 100 lines------'>>diff.out");
//	execute_cmd("head -100 data.in>>diff.out");
//	execute_cmd("echo '------test out top 100 lines-----'>>diff.out");
//	execute_cmd("head -100 '%s'>>diff.out", path);
//	execute_cmd("echo '------user out top 100 lines-----'>>diff.out");
//	execute_cmd("head -100 user.out>>diff.out");
//	execute_cmd("echo '------diff out 200 lines-----'>>diff.out");
//	execute_cmd("diff '%s' user.out -y|head -200>>diff.out", path);
//	execute_cmd("echo '=============================='>>diff.out");
//}
void make_diff_out(FILE *f1, FILE *f2, int c1, int c2, const char *path) {

//	execute_cmd("echo '========[%s]========='>>diff.out", getFileNameFromPath(path));
//	execute_cmd("echo 'Expected						      |	Yours'>>diff.out");
//	execute_cmd("diff '%s' user.out -y|head -100>>diff.out", path);
//	execute_cmd("echo '\n=============================='>>diff.out");
	execute_cmd("rm diff.out");
	execute_cmd("diff '%s' user.out -y|head -100>>diff.out", path);
}

/*
 * translated from ZOJ judger r367
 * http://code.google.com/p/zoj/source/browse/trunk/judge_client/client/text_checker.cc#25
 *
 */
int compare_zoj(const char *file1, const char *file2) {

	int ret = OJ_AC;
	int c1, c2;
	FILE *f1, *f2;
	f1 = fopen(file1, "re");
	f2 = fopen(file2, "re");
	if (!f1 || !f2) {
		ret = OJ_RE;
	} else
		for (;;) {
			// Find the first non-space character at the beginning of line.
			// Blank lines are skipped.
			c1 = fgetc(f1);
			c2 = fgetc(f2);
			find_next_nonspace(c1, c2, f1, f2, ret);
			// Compare the current line.
			for (;;) {
				// Read until 2 files return a space or 0 together.
				while ((!isspace(c1) && c1) || (!isspace(c2) && c2)) {
					if (c1 == EOF && c2 == EOF) {
						goto end;
					}
					if (c1 == EOF || c2 == EOF) {
						break;
					}
					if (c1 != c2) {
						// Consecutive non-space characters should be all exactly the ifconfig|grep 'inet'|awk -F: '{printf $2}'|awk  '{printf $1}'same
						ret = OJ_WA;
						goto end;
					}
					c1 = fgetc(f1);
					c2 = fgetc(f2);
				}
				find_next_nonspace(c1, c2, f1, f2, ret);
				if (c1 == EOF && c2 == EOF) {
					goto end;
				}
				if (c1 == EOF || c2 == EOF) {
					ret = OJ_WA;
					goto end;
				}

				if ((c1 == '\n' || !c1) && (c2 == '\n' || !c2)) {
					break;
				}
			}
		}
end:
//	printf("%s %s\n",file1,file2);
	if (ret == OJ_WA || ret == OJ_PE) {

//		printf("------------%s\n",file1);
		make_diff_out(f1, f2, c1, c2, file1);
	}
	if (f1)
		fclose(f1);
	if (f2)
		fclose(f2);
	return ret;
}

void delnextline(char s[]) {
	int L;
	L = strlen(s);
	while (L > 0 && (s[L - 1] == '\n' || s[L - 1] == '\r'))
		s[--L] = 0;
}

int compare(const char *file1, const char *file2) {
#ifdef ZOJ_COM
	//compare ported and improved from zoj don't limit file size
	return compare_zoj(file1, file2);
#endif

#ifndef ZOJ_COM
	//the original compare from the first version of codeoj has file size limit
	//and waste memory
	FILE *f1, *f2;
	char *s1, *s2, *p1, *p2;
	int PEflg;
	s1 = new char[STD_F_LIM + 512];
	s2 = new char[STD_F_LIM + 512];
	if (!(f1 = fopen(file1, "re")))
		return OJ_AC;
	for (p1 = s1; EOF != fscanf(f1, "%s", p1);)
		while (*p1)
			p1++;
	fclose(f1);
	if (!(f2 = fopen(file2, "re")))
		return OJ_RE;
	for (p2 = s2; EOF != fscanf(f2, "%s", p2);)
		while (*p2)
			p2++;
	fclose(f2);
	if (strcmp(s1, s2) != 0) {
		//              printf("A:%s\nB:%s\n",s1,s2);
		delete[] s1;
		delete[] s2;

		return OJ_WA;
	} else {
		f1 = fopen(file1, "re");
		f2 = fopen(file2, "re");
		PEflg = 0;
		while (PEflg == 0 && fgets(s1, STD_F_LIM, f1) && fgets(s2, STD_F_LIM, f2)) {
			delnextline(s1);
			delnextline(s2);
			if (strcmp(s1, s2) == 0)
				continue;
			else
				PEflg = 1;
		}
		delete[] s1;
		delete[] s2;
		fclose(f1);
		fclose(f2);
		if (PEflg)
			return OJ_PE;
		else
			return OJ_AC;
	}
#endif
}


void clean_task(int status_id) {
	char sql[(1 << 16)];
	snprintf(sql, (1 << 16) - 1, "DELETE FROM status_task WHERE status_id=%d",
	         status_id);
	mysql_real_query(conn, sql, strlen(sql));

}


void update_status(int status_id, int result, int time, int memory, int score) {
	if (result == OJ_TL && memory == 0)
		result = OJ_ML;

	char sql[BUFFER_SIZE];
	char judger[BUFFER_SIZE];
	mysql_real_escape_string(conn, judger, judge_name, strlen(judge_name));


//		sprintf(sql,
//		        "UPDATE %s SET result=%d,time=%d,memory=%d,score=%f,judger='%s',judge_time=now() WHERE status_id=%d ",
//		        tbname,	    result, time,   memory,   score,  judger, status_id);
	sprintf(sql,
	        "UPDATE %s SET result=%d,time=%d,memory=%d,score=%d,judger='%s',judge_time=now() WHERE status_id=%d ",
	        tbname,	    result, time,   memory,   score,  judger, status_id);

	//      printf("sql= %s\n",sql);
	if (mysql_real_query(conn, sql, strlen(sql))) {
		//              printf("..update failed! %s\n",mysql_error(conn));
	}


}
/* write compile error message back to database */

void _addceinfo_mysql(int status_id) {
	char sql[(1 << 16)], *end;
	char ceinfo[(1 << 16)], *cend;
	FILE *fp = fopen("ce.txt", "re");
	snprintf(sql, (1 << 16) - 1, "DELETE FROM status_info WHERE status_id=%d",
	         status_id);
	mysql_real_query(conn, sql, strlen(sql));
	cend = ceinfo;
	while (fgets(cend, 1024, fp)) {
		cend += strlen(cend);
		if (cend - ceinfo > 40000)
			break;
	}
	*cend = '\0';
	end = sql;
	strcpy(end, "INSERT INTO status_info VALUES(");
	end += strlen(sql);
	*end++ = '\'';
	end += sprintf(end, "%d", status_id);
	*end++ = '\'';
	*end++ = ',';
	*end++ = '\'';
	end += mysql_real_escape_string(conn, end, ceinfo, strlen(ceinfo));
	*end++ = '\'';
	*end++ = ')';
	*end = 0;
	//      printf("%s\n",ceinfo);
	if (mysql_real_query(conn, sql, end - sql))
		printf("%s\n", mysql_error(conn));
	fclose(fp);
}

// urlencoded function copied from http://www.geekhideout.com/urlcode.shtml
/* Converts a hex character to its integer value */
char from_hex(char ch) {
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
char to_hex(char code) {
	static char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(char *str) {
	char *pstr = str, *buf = (char *)malloc(strlen(str) * 3 + 1), *pbuf = buf;
	while (*pstr) {
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
			*pbuf++ = *pstr;
		else if (*pstr == ' ')
			*pbuf++ = '+';
		else
			*pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
		pstr++;
	}
	*pbuf = '\0';
	return buf;
}

void addceinfo(int status_id) {

	_addceinfo_mysql(status_id);

}
/* write runtime error message back to database */

void add_task_info(int status_id,int task_id,int result,int time,int mem, const char *filename) {
	printf("%s\n",filename);
	char sql[(1 << 16)], *end;
	char reinfo[(1 << 16)], *rend;
	FILE *fp = fopen(filename, "re");
	if(fp==NULL){
		fp = fopen(filename, "w");
	}
	rend = reinfo;
	while (fgets(rend, 1024, fp)) {
		rend += strlen(rend);
		if (rend - reinfo > 40000)
			break;
	}
	
	
	*rend = '\0';
	end = sql;
	strcpy(end, "INSERT INTO status_task VALUES(");

	end += strlen(sql);
	*end++ = '\'';
	end += sprintf(end, "%d", status_id);
	*end++ = '\'';
	*end++ = ',';
	*end++ = '\'';
	end += sprintf(end, "%d", task_id);
	*end++ = '\'';
	*end++ = ',';
	*end++ = '\'';
	end += sprintf(end, "%d", result);
	*end++ = '\'';
	*end++ = ',';
	*end++ = '\'';
	end += sprintf(end, "%d", time);
	*end++ = '\'';
	*end++ = ',';
	*end++ = '\'';
	end += sprintf(end, "%d", mem);
	*end++ = '\'';
	*end++ = ',';
	*end++ = '\'';
	end += mysql_real_escape_string(conn, end, reinfo, strlen(reinfo));
	*end++ = '\'';
	*end++ = ')';
	*end = 0;

	if (mysql_real_query(conn, sql, end - sql))
		printf("%s\n", mysql_error(conn));
	fclose(fp);
	
	
}

void addcustomout(int status_id,int task_id,int time,int mem) {

	add_task_info(status_id,task_id,OJ_TR,time,mem, "user.out");

}

void update_problem(int p_id,int cid) {

	char sql[BUFFER_SIZE];
	if(cid>0) {
		sprintf(sql,
		        "UPDATE `contest_problem` SET `c_accepted`=(SELECT count(*) FROM `status` WHERE `problem_id`=%d AND `result`=4 and contest_id=%d) WHERE `problem_id`=%d and contest_id=%d",
		        p_id,cid, p_id,cid);
		printf("sql:[%s]\n",sql);
		if (mysql_real_query(conn, sql, strlen(sql)))
			write_log(mysql_error(conn));

	}

	sprintf(sql,
	        "UPDATE `problem` SET `accept`=(SELECT count(*) FROM `status` WHERE `problem_id`=%d AND `result`=4) WHERE `problem_id`=%d",
	        p_id, p_id);
	printf("sql:[%s]\n",sql);
	if (mysql_real_query(conn, sql, strlen(sql)))
		write_log(mysql_error(conn));
	if(cid>0) {
		sprintf(sql,
		        "UPDATE `contest_problem` SET `c_submit`=(SELECT count(*) FROM `status` WHERE `problem_id`=%d AND  contest_id=%d) WHERE `problem_id`=%d and contest_id=%d",
		        p_id,cid, p_id,cid);
		if (mysql_real_query(conn, sql, strlen(sql)))
			write_log(mysql_error(conn));
	}
	sprintf(sql,
	        "UPDATE `problem` SET `attempt`=(SELECT count(*) FROM `status` WHERE `problem_id`=%d) WHERE `problem_id`=%d",
	        p_id, p_id);


	if (mysql_real_query(conn, sql, strlen(sql)))
		write_log(mysql_error(conn));

}
void umount(char *work_dir) {
	execute_cmd("/bin/umount -f %s/proc 2>/dev/null", work_dir);
	execute_cmd("/bin/umount -f %s/dev 2>/dev/null", work_dir);
	execute_cmd("/bin/umount -f %s/lib 2>/dev/null", work_dir);
	execute_cmd("/bin/umount -f %s/lib64 2>/dev/null", work_dir);
	execute_cmd("/bin/umount -f %s/etc/alternatives 2>/dev/null", work_dir);
	execute_cmd("/bin/umount -f %s/usr 2>/dev/null", work_dir);
	execute_cmd("/bin/umount -f %s/bin 2>/dev/null", work_dir);
	execute_cmd("/bin/umount -f %s/proc 2>/dev/null", work_dir);
	execute_cmd("/bin/umount -f bin usr lib lib64 etc/alternatives proc dev 2>/dev/null");
	execute_cmd("/bin/umount -f %s/* 2>/dev/null", work_dir);
	execute_cmd("/bin/umount -f %s/log/* 2>/dev/null", work_dir);
    execute_cmd("/bin/umount -f %s/log/etc/alternatives 2>/dev/null", work_dir);
}
int compile(int lang, char *work_dir) {
	int pid;

	const char *CP_C[] = {"gcc", "Main.c", "-o", "Main", "-O2", "-fmax-errors=10", "-Wall",
	                      "-lm", "--static", "-std=c99", "-DONLINE_JUDGE", NULL
	                     };
	const char *CP_X[] = {"g++", "-fno-asm", "-fmax-errors=10", "-Wall",
	                      "-lm", "--static", "-std=c++11", "-DONLINE_JUDGE", "-o", "Main", "Main.cc", NULL
	                     };
	const char *CP_P[] =
	{"fpc", "Main.pas", "-Cs32000000", "-Sh", "-O2", "-Co", "-Ct", "-Ci", NULL};
	//      const char * CP_J[] = { "javac", "-J-Xms32m", "-J-Xmx256m","-encoding","UTF-8", "Main.java",NULL };

	const char *CP_R[] = {"ruby", "-c", "Main.rb", NULL};
	const char *CP_B[] = {"chmod", "+rx", "Main.sh", NULL};
	//const char * CP_Y[] = { "python", "-c",
	//		"import py_compile; py_compile.compile(r'Main.py')", NULL };
	const char *CP_PH[] = {"php", "-l", "Main.php", NULL};
	const char *CP_PL[] = {"perl", "-c", "Main.pl", NULL};
	const char *CP_CS[] = {"gmcs", "-warn:0", "Main.cs", NULL};
	const char *CP_OC[] = {"gcc", "-o", "Main", "Main.m",
	                       "-fconstant-string-class=NSConstantString", "-I",
	                       "/usr/include/GNUstep/", "-L", "/usr/lib/GNUstep/Libraries/",
	                       "-lobjc", "-lgnustep-base", NULL
	                      };
	const char *CP_BS[] = {"fbc", "-lang", "qb", "Main.bas", NULL};
	const char *CP_CLANG[] = {"clang", "Main.c", "-o", "Main", "-ferror-limit=10", "-fno-asm", "-Wall",
	                          "-lm", "--static", "-std=c99", "-DONLINE_JUDGE", NULL
	                         };
	const char *CP_CLANG_CPP[] = {"clang++", "Main.cc", "-o", "Main", "-ferror-limit=10", "-fno-asm", "-Wall",
	                              "-lm", "--static", "-std=c++0x", "-DONLINE_JUDGE", NULL
	                             };
	const char *CP_LUA[] = {"luac", "-o", "Main", "Main.lua", NULL};
	//const char * CP_JS[] = { "js24","-c", "Main.js", NULL };
	const char *CP_GO[] = {"go", "build", "-o", "Main", "Main.go", NULL};
	const char *CP_FORTRAN[] = {"f95", "-static", "-o", "Main", "Main.f95", NULL};

	char javac_buf[7][32];
	char *CP_J[7];

	for (int i = 0; i < 7; i++)
		CP_J[i] = javac_buf[i];

	sprintf(CP_J[0], "javac");
	sprintf(CP_J[1], "-J%s", java_xms);
	sprintf(CP_J[2], "-J%s", java_xmx);
	sprintf(CP_J[3], "-encoding");
	sprintf(CP_J[4], "UTF-8");
	sprintf(CP_J[5], "Main.java");
	CP_J[6] = (char *)NULL;

	pid = fork();
	if (pid == 0) {
		struct rlimit LIM;
		int cpu = 6;
		if (lang == 3)
			cpu = 30;
		LIM.rlim_max = cpu;
		LIM.rlim_cur = cpu;
		setrlimit(RLIMIT_CPU, &LIM);
		alarm(cpu);
		LIM.rlim_max = 40 * STD_MB;
		LIM.rlim_cur = 40 * STD_MB;
		setrlimit(RLIMIT_FSIZE, &LIM);

		if (lang == 3 || lang == 17) {
#ifdef __mips__
			LIM.rlim_max = STD_MB << 12;
			LIM.rlim_cur = STD_MB << 12;
#endif
#ifdef __arm__
			LIM.rlim_max = STD_MB << 11;
			LIM.rlim_cur = STD_MB << 11;
#endif
#ifdef __i386__
			LIM.rlim_max = STD_MB << 11;
			LIM.rlim_cur = STD_MB << 11;
#endif
#ifdef __x86_64__
			LIM.rlim_max = STD_MB << 12;
			LIM.rlim_cur = STD_MB << 12;
#endif
		} else {
			LIM.rlim_max = STD_MB * 512;
			LIM.rlim_cur = STD_MB * 512;
		}
		if (lang != 3)
			setrlimit(RLIMIT_AS, &LIM);
		if (lang != 2 && lang != 11) {
			freopen("ce.txt", "w", stderr);
			//freopen("/dev/null", "w", stdout);
		} else {
			freopen("ce.txt", "w", stdout);
		}
		execute_cmd("/bin/chown judge %s ", work_dir);
		execute_cmd("/bin/chmod 700 %s ", work_dir);

		if (compile_chroot && lang != 3 && lang != 9 && lang != 6 && lang != 11) {
			execute_cmd("mkdir -p bin usr lib lib64 etc/alternatives proc tmp dev");
			execute_cmd("chown judge *");
			execute_cmd("mount -o bind /bin bin");
			execute_cmd("mount -o remount,ro bin");
			execute_cmd("mount -o bind /usr usr");
			execute_cmd("mount -o remount,ro usr");
			execute_cmd("mount -o bind /lib lib");
			execute_cmd("mount -o remount,ro lib");
#ifndef __i386__
			execute_cmd("mount -o bind /lib64 lib64");
			execute_cmd("mount -o remount,ro lib64");
#endif
			execute_cmd("mount -o bind /etc/alternatives etc/alternatives");
			execute_cmd("mount -o remount,ro etc/alternatives");
			execute_cmd("mount -t proc /proc proc");
			if (lang > 2 && lang != 10 && lang != 13 && lang != 14 && lang != 17) {
				execute_cmd("mkdir -p bin usr lib lib64 etc/alternatives proc tmp dev");
				execute_cmd("mount -o bind /dev dev");
				execute_cmd("mount -o remount,ro dev");
			}
			//execute_cmd("mount -o remount,ro proc");
			chroot(work_dir);
		}
		while (setgid(1536) != 0)
			sleep(1);
		while (setuid(1536) != 0)
			sleep(1);
		while (setresuid(1536, 1536, 1536) != 0)
			sleep(1);

		switch (lang) {
			case 0:
				execvp(CP_C[0], (char *const *)CP_C);
				break;
			case 1:
				execvp(CP_X[0], (char *const *)CP_X);
				break;
			case 2:
				execvp(CP_P[0], (char *const *)CP_P);
				break;
			case 3:
				execvp(CP_J[0], (char *const *)CP_J);
				break;
			case 4:
				execvp(CP_R[0], (char *const *)CP_R);
				break;
			case 5:
				execvp(CP_B[0], (char *const *)CP_B);
				break;
				//case 6:
				//	execvp(CP_Y[0], (char * const *) CP_Y);
				//	break;
			case 7:
				execvp(CP_PH[0], (char *const *)CP_PH);
				break;
			case 8:
				execvp(CP_PL[0], (char *const *)CP_PL);
				break;
			case 9:
				execvp(CP_CS[0], (char *const *)CP_CS);
				break;

			case 10:
				execvp(CP_OC[0], (char *const *)CP_OC);
				break;
			case 11:
				execvp(CP_BS[0], (char *const *)CP_BS);
				break;
			case 13:
				execvp(CP_CLANG[0], (char *const *)CP_CLANG);
				break;
			case 14:
				execvp(CP_CLANG_CPP[0], (char *const *)CP_CLANG_CPP);
				break;
			case 15:
				execvp(CP_LUA[0], (char *const *)CP_LUA);
				break;
				//case 16:
				//	execvp(CP_JS[0], (char * const *) CP_JS);
				//	break;
			case 17:
				execvp(CP_GO[0], (char *const *)CP_GO);
				break;
			case 19:
				execvp(CP_FORTRAN[0], (char *const *)CP_FORTRAN);
				break;
			default:
				printf("nothing to do!\n");
		}
		if (DEBUG)
			printf("compile end!\n");
		//exit(!system("cat ce.txt"));
		exit(0);
	} else {
		int status = 0;

		waitpid(pid, &status, 0);
		if (lang > 3 && lang < 7)
			status = get_file_size("ce.txt");
		if (DEBUG)
			printf("status=%d\n", status);
		execute_cmd("/bin/umount -f bin usr lib lib64 etc/alternatives proc dev 2>/dev/null");
		execute_cmd("/bin/umount -f %s/* 2>/dev/null", work_dir);
		umount(work_dir);

		return status;
	}
}
/*
 int read_proc_statm(int pid){
 FILE * pf;
 char fn[4096];
 int ret;
 sprintf(fn,"/proc/%d/statm",pid);
 pf=fopen(fn,"r");
 fscanf(pf,"%d",&ret);
 fclose(pf);
 return ret;
 }
 */
int get_proc_status(int pid, const char *mark) {
	FILE *pf;
	char fn[BUFFER_SIZE], buf[BUFFER_SIZE];
	int ret = 0;
	sprintf(fn, "/proc/%d/status", pid);
	pf = fopen(fn, "re");
	int m = strlen(mark);
	while (pf && fgets(buf, BUFFER_SIZE - 1, pf)) {

		buf[strlen(buf) - 1] = 0;
		if (strncmp(buf, mark, m) == 0) {
			sscanf(buf + m + 1, "%d", &ret);
		}
	}
	if (pf)
		fclose(pf);
	return ret;
}

int init_mysql_conn() {

	conn = mysql_init(NULL);
	//mysql_real_connect(conn,host_name,user_name,password,db_name,port_number,0,0);
	const char timeout = 30;
	mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);

	if (!mysql_real_connect(conn, host_name, user_name, password, db_name,
	                        port_number, 0, 0)) {
		write_log("%s", mysql_error(conn));
		return 0;
	}
	const char *utf8sql = "set names utf8";
	if (mysql_real_query(conn, utf8sql, strlen(utf8sql))) {
		write_log("%s", mysql_error(conn));
		return 0;
	}
	return 1;
}

void _get_status_mysql(int status_id, char *work_dir, int lang) {
	char sql[BUFFER_SIZE], src_pth[BUFFER_SIZE];
	// get the status_code code
	MYSQL_RES *res;
	MYSQL_ROW row;
	sprintf(sql, "SELECT code FROM status_code WHERE status_id=%d",
	        status_id);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	row = mysql_fetch_row(res);

	printf("%s", row[0]);

	// create the src file
	sprintf(src_pth, "Main.%s", lang_ext[lang]);
	if (DEBUG)
		printf("Main=%s", src_pth);
	FILE *fp_src = fopen(src_pth, "we");
	fprintf(fp_src, "%s", row[0]);
	if (res != NULL) {
		mysql_free_result(res); // free the memory
		res = NULL;
	}
	fclose(fp_src);
}

void get_status(int status_id, char *work_dir, int lang) {
	char src_pth[BUFFER_SIZE];
	sprintf(src_pth, "Main.%s", lang_ext[lang]);

	_get_status_mysql(status_id, work_dir, lang);

	if(lang == 6 ) {
		py2 = execute_cmd("/bin/grep 'python2' %s/Main.py > /dev/null", work_dir);
	}
	execute_cmd("chown judge %s/%s", work_dir, src_pth);
}


void _get_custominput_mysql(int status_id, char *work_dir) {
	char sql[BUFFER_SIZE], src_pth[BUFFER_SIZE];
	// get the source code
	MYSQL_RES *res;
	MYSQL_ROW row;
	sprintf(sql, "SELECT input FROM status_data WHERE status_id=%d",
	        status_id);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	row = mysql_fetch_row(res);
	if (row != NULL) {

		// create the src file
		sprintf(src_pth, "data.in");
		FILE *fp_src = fopen(src_pth, "w");
		fprintf(fp_src, "%s", row[0]);
		fclose(fp_src);
	}
	if (res != NULL) {
		mysql_free_result(res); // free the memory
		res = NULL;
	}
}

void get_custominput(int status_id, char *work_dir) {

	_get_custominput_mysql(status_id, work_dir);

}
void _get_status_info_mysql(int status_id, int & p_id, char * user_id,
                            int & lang,int &cid) {

	MYSQL_RES *res;
	MYSQL_ROW row;

	char sql[BUFFER_SIZE];
	// get the problem id and user id from Table:status

	sprintf(sql,
	        "SELECT problem_id, creator, language FROM status where status_id=%d",
	        status_id);



	//printf("%s\n",sql);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	row = mysql_fetch_row(res);
	p_id = atoi(row[0]);
	strcpy(user_id, row[1]);
	lang = atoi(row[2]);

	/*codeoj*/
	/*选取contest_id*/
//	if(row[3]==NULL)
	cid=0;
//	else
//	cid = atoi(row[3]);
	printf("cid:%d\n",cid);
	if(res!=NULL) {
		mysql_free_result(res);                         // free the memory
		res=NULL;
	}
}
void get_status_info(int status_id, int & p_id, char * user_id,
                     int & lang,int & cid) {


	_get_status_info_mysql(status_id, p_id, user_id, lang,cid);

}


void _get_problem_info_mysql(int p_id, int &time_lmt, int &mem_lmt,
                             int &isspj) {
	// get the problem info from Table:problem
	char sql[BUFFER_SIZE];
	MYSQL_RES *res;
	MYSQL_ROW row;
	sprintf(sql,
	        "SELECT time_limit,memory_limit,judge_type FROM problem where problem_id=%d",
	        p_id);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	row = mysql_fetch_row(res);
	time_lmt = atoi(row[0]);
	mem_lmt = atoi(row[1]);
	isspj = (row[2][0] == '1');
	if (res != NULL) {
		mysql_free_result(res); // free the memory
		res = NULL;
	}
}


void get_problem_info(int p_id, int &time_lmt, int &mem_lmt, int &isspj) {

	_get_problem_info_mysql(p_id, time_lmt, mem_lmt, isspj);


	if (time_lmt <= 0)
		time_lmt = 1;
}
char *escape(char s[], char t[]) {
	int i, j;
	for (i = j = 0; t[i] != '\0'; ++i) {
		if (t[i] == '\'') {
			s[j++] = '\'';
			s[j++] = '\\';
			s[j++] = '\'';
			s[j++] = '\'';
			continue;
		} else {
			s[j++] = t[i];
		}
	}
	s[j] = '\0';
	return s;
}

void prepare_files(char *filename, int namelen, char *infile, int &p_id,
                   char *work_dir, char *outfile, char *userfile, int runner_id) {
	//              printf("ACflg=%d %d check a file!\n",ACflg,status_id);

	char fname0[BUFFER_SIZE];
	char fname[BUFFER_SIZE];
	strncpy(fname0, filename, namelen);

	fname0[namelen] = 0;
	escape(fname, fname0);
	//printf("%s\n%s\n",fname0,fname);
	sprintf(infile, "%s/data/%d/%s.in", oj_home, p_id, fname);

	execute_cmd("/bin/cp '%s' %s/data.in", infile, work_dir);
	execute_cmd("/bin/cp %s/data/%d/*.dic %s/ 2>/dev/null", oj_home, p_id, work_dir);

	sprintf(outfile, "%s/data/%d/%s.out", oj_home, p_id, fname0);
	sprintf(userfile, "%s/run%d/user.out", oj_home, runner_id);
	
	execute_cmd("rm %s/error.out",work_dir);
}

void cp_data_files(char *work_dir,char *infileName,char *outfileName,
                   int p_id,char *infile,char *outfile,char *userfile, int runner_id) {

	sprintf(infile, "%s/data/%d/%s", oj_home, p_id, infileName);

	if (access(infile, 0) != -1) {
		execute_cmd("/bin/cp '%s' %s/data.in", infile, work_dir);
	}
	sprintf(outfile, "%s/data/%d/%s", oj_home, p_id, outfileName);
	if (access(outfile, 0) != -1) {
		execute_cmd("/bin/cp '%s' %s/data.out", outfile, work_dir);
	}
	execute_cmd("/bin/cp %s/data/%d/*.dic %s/ 2>/dev/null", oj_home, p_id, work_dir);
	sprintf(userfile, "%s/run%d/user.out", oj_home, runner_id);
	
	execute_cmd("rm %s/error.out",work_dir);
	
}

void prepare_extra_files(char *filename,int &p_id,char *work_dir) {
	execute_cmd("/bin/cp %s/data/%d/%s %s/%s", oj_home,p_id,filename, work_dir,filename);
}


void copy_shell_runtime(char *work_dir) {

	execute_cmd("/bin/mkdir %s/lib", work_dir);
	execute_cmd("/bin/mkdir %s/lib64", work_dir);
	execute_cmd("/bin/mkdir %s/bin", work_dir);
#ifdef __mips__
	execute_cmd("/bin/cp -a /lib64/ld.so.1  %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libdl.so.2  %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libc.so.6 %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libtinfo.so.6  %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/ld-2.27.so  %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libc-2.27.so %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libdl-2.27.so %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libtinfo.so.6.1 %s/lib64/", work_dir);

#endif

#ifdef __i386
	execute_cmd("/bin/cp /lib/ld-linux* %s/lib/", work_dir);
	execute_cmd("/bin/cp -a /lib/i386-linux-gnu/  %s/lib/", work_dir);
//	execute_cmd("/bin/cp -a /usr/lib/i386-linux-gnu %s/lib/", work_dir);
#endif

#ifdef __x86_64__
	execute_cmd("/bin/cp -a /lib/x86_64-linux-gnu %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib64/* %s/lib64/", work_dir);
#endif
	//	execute_cmd("/bin/cp /lib32 %s/", work_dir);
	execute_cmd("/bin/cp /bin/busybox %s/bin/", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/sh", work_dir);
	execute_cmd("/bin/cp /bin/bash %s/bin/bash", work_dir);
}
void copy_objc_runtime(char *work_dir) {
	copy_shell_runtime(work_dir);
	execute_cmd("/bin/mkdir -p %s/proc", work_dir);
	execute_cmd("/bin/mount -o bind /proc %s/proc", work_dir);
	execute_cmd("/bin/mount -o remount,ro %s/proc", work_dir);
	execute_cmd("/bin/mkdir -p %s/lib/", work_dir);
	execute_cmd(
	    "/bin/cp -aL /lib/libdbus-1.so.3                          %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /lib/libgcc_s.so.1                           %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /lib/libgcrypt.so.11                         %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /lib/libgpg-error.so.0                       %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /lib/libz.so.1                               %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /lib/tls/i686/cmov/libc.so.6                 %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /lib/tls/i686/cmov/libdl.so.2                %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /lib/tls/i686/cmov/libm.so.6                 %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /lib/tls/i686/cmov/libnsl.so.1               %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /lib/tls/i686/cmov/libpthread.so.0           %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /lib/tls/i686/cmov/librt.so.1                %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /usr/lib/libavahi-client.so.3                %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /usr/lib/libavahi-common.so.3                %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /usr/lib/libdns_sd.so.1                      %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /usr/lib/libffi.so.5                         %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /usr/lib/libgnustep-base.so.1.19             %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /usr/lib/libgnutls.so.26                     %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /usr/lib/libobjc.so.2                        %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /usr/lib/libtasn1.so.3                       %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /usr/lib/libxml2.so.2                        %s/lib/ ",
	    work_dir);
	execute_cmd(
	    "/bin/cp -aL /usr/lib/libxslt.so.1                        %s/lib/ ",
	    work_dir);
}
void copy_bash_runtime(char *work_dir) {
	//char cmd[BUFFER_SIZE];
	//const char * ruby_run="/usr/bin/ruby";
	copy_shell_runtime(work_dir);
	execute_cmd("/bin/cp `which bc`  %s/bin/", work_dir);
	execute_cmd("busybox dos2unix Main.sh", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/grep", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/awk", work_dir);
	execute_cmd("/bin/cp /bin/sed %s/bin/sed", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/cut", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/sort", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/join", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/wc", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/tr", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/dc", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/dd", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/cat", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/tail", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/head", work_dir);
	execute_cmd("/bin/ln -s /bin/busybox %s/bin/xargs", work_dir);
	execute_cmd("chmod +rx %s/Main.sh", work_dir);
}
void copy_ruby_runtime(char *work_dir) {

	copy_shell_runtime(work_dir);
	execute_cmd("mkdir -p %s/usr", work_dir);
	execute_cmd("mkdir -p %s/usr/lib", work_dir);
	execute_cmd("mkdir -p %s/usr/lib64", work_dir);
	execute_cmd("cp -a /usr/lib/libruby* %s/usr/lib/", work_dir);
	execute_cmd("cp -a /usr/lib/ruby* %s/usr/lib/", work_dir);
	execute_cmd("cp -a /usr/lib64/ruby* %s/usr/lib64/", work_dir);
	execute_cmd("cp -a /usr/lib64/libruby* %s/usr/lib64/", work_dir);
	execute_cmd("cp -a /usr/bin/ruby* %s/", work_dir);
#ifdef __x86_64__
	execute_cmd("/bin/cp -a /usr/lib/x86_64-linux-gnu/libruby* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp -a /usr/lib/x86_64-linux-gnu/libgmp* %s/usr/lib/", work_dir);
#endif
}

void copy_guile_runtime(char *work_dir) {

	copy_shell_runtime(work_dir);
	execute_cmd("/bin/mkdir -p %s/proc", work_dir);
	execute_cmd("/bin/mount -o bind /proc %s/proc", work_dir);
	execute_cmd("/bin/mount -o remount,ro %s/proc", work_dir);
	execute_cmd("/bin/mkdir -p %s/usr/lib", work_dir);
	execute_cmd("/bin/mkdir -p %s/usr/share", work_dir);
	execute_cmd("/bin/cp -a /usr/share/guile %s/usr/share/", work_dir);
	execute_cmd("/bin/cp /usr/lib/libguile* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/libgc* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/i386-linux-gnu/libffi* %s/usr/lib/",
	            work_dir);
	execute_cmd("/bin/cp /usr/lib/i386-linux-gnu/libunistring* %s/usr/lib/",
	            work_dir);
	execute_cmd("/bin/cp /usr/lib/*/libgmp* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/libgmp* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/*/libltdl* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/libltdl* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/bin/guile* %s/", work_dir);
#ifdef __x86_64__
	execute_cmd("/bin/cp -a /usr/lib/x86_64-linux-gnu/libguile* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp -a /usr/lib/x86_64-linux-gnu/libgc* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp -a /usr/lib/x86_64-linux-gnu/libffi* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp -a /usr/lib/x86_64-linux-gnu/libunistring* %s/usr/lib/", work_dir);
#endif
}

void copy_python_runtime(char *work_dir) {

	copy_shell_runtime(work_dir);
	execute_cmd("mkdir -p %s/usr/include", work_dir);
	execute_cmd("mkdir -p %s/dev", work_dir);
	execute_cmd("mkdir -p %s/usr/lib", work_dir);
	execute_cmd("mkdir -p %s/usr/lib64", work_dir);
	execute_cmd("mkdir -p %s/usr/local/lib", work_dir);

	// /etc/abrt/plugins/python.conf for Centos7
	execute_cmd("mkdir -p %s/etc/abrt", work_dir);
	execute_cmd("mkdir -p %s/etc/abrt/plugins", work_dir);
	execute_cmd("cp -a /etc/abrt/plugins/python.conf %s/etc/abrt/plugins/python.conf", work_dir);

	// /usr/share/abrt/conf.d/plugins/python.conf for Centos7
	execute_cmd("mkdir -p %s/usr/share", work_dir);
	execute_cmd("mkdir -p %s/usr/share/abrt/", work_dir);
	execute_cmd("mkdir -p %s/usr/share/abrt/conf.d", work_dir);
	execute_cmd("mkdir -p %s/usr/share/abrt/conf.d/plugins", work_dir);
	execute_cmd("cp -a /usr/share/abrt/conf.d/plugins/python.conf %s/usr/share/abrt/conf.d/plugins/python.conf", work_dir);
	if(!py2) {
		execute_cmd("cp /usr/bin/python2* %s/", work_dir);
#if (defined __i386) || (defined __arm__) || (defined __x86_64__)
		execute_cmd("cp -a /usr/lib/python2* %s/usr/lib/", work_dir);
#endif
#if (defined __mips__)
		execute_cmd("cp -a /usr/lib64/python2* %s/usr/lib64/", work_dir);
#endif
	} else {
		execute_cmd("cp /usr/bin/python3* %s/", work_dir);
#if (defined __i386) || (defined __arm__) || (defined __x86_64__)
		execute_cmd("cp -a /usr/lib/python3* %s/usr/lib/", work_dir);
#endif
#if (defined __mips__)
		execute_cmd("cp -a /usr/lib64/python3* %s/usr/lib64/", work_dir);
#endif
	}
#ifdef __mips__
	execute_cmd("/bin/cp -a /lib64/libpthread.so.0 %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libutil.so.1 %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libm.so.6 %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libc.so.6 %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libpthread-2.27.so %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libutil-2.27.so %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libc-2.27.so %s/lib64/", work_dir);
	execute_cmd("/bin/cp -a /lib64/libm-2.27.so %s/lib64/", work_dir);


#endif
	execute_cmd("cp -a /usr/lib64/libpython* %s/usr/lib64/", work_dir);
	execute_cmd("cp -a /usr/local/lib/python* %s/usr/local/lib/", work_dir);
	execute_cmd("cp -a /usr/include/python* %s/usr/include/", work_dir);
	execute_cmd("cp -a /usr/lib/libpython* %s/usr/lib/", work_dir);
	execute_cmd("/bin/mkdir -p %s/home/judge", work_dir);
	execute_cmd("/bin/chown judge %s", work_dir);
	execute_cmd("/bin/mkdir -p %s/etc", work_dir);
	execute_cmd("/bin/grep judge /etc/passwd>%s/etc/passwd", work_dir);
	execute_cmd("/bin/mount -o bind /dev %s/dev", work_dir);
	execute_cmd("/bin/mount -o remount,ro %s/dev", work_dir);
}
void copy_php_runtime(char *work_dir) {

	copy_shell_runtime(work_dir);
	execute_cmd("/bin/mkdir %s/usr", work_dir);
	execute_cmd("/bin/mkdir %s/usr/lib", work_dir);
	execute_cmd("/bin/cp /usr/lib/libedit* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/libdb* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/libgssapi_krb5* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/libkrb5* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/libk5crypto* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/*/libedit* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/*/libdb* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/*/libgssapi_krb5* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/*/libkrb5* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/*/libk5crypto* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/libxml2* %s/usr/lib/", work_dir);
#ifdef __x86_64__
	execute_cmd("/bin/cp /usr/lib/x86_64-linux-gnu/libxml2.so* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/x86_64-linux-gnu/libicuuc.so* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/x86_64-linux-gnu/libicudata.so* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/x86_64-linux-gnu/libstdc++.so* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/x86_64-linux-gnu/libssl* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/lib/x86_64-linux-gnu/libcrypto* %s/usr/lib/", work_dir);
#endif
	execute_cmd("/bin/cp /usr/bin/php* %s/", work_dir);
	execute_cmd("chmod +rx %s/Main.php", work_dir);
}
void copy_perl_runtime(char *work_dir) {

	copy_shell_runtime(work_dir);
	execute_cmd("/bin/mkdir %s/usr", work_dir);
	execute_cmd("/bin/mkdir %s/usr/lib", work_dir);
	execute_cmd("/bin/cp /usr/lib/libperl* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /usr/bin/perl* %s/", work_dir);
}
void copy_freebasic_runtime(char *work_dir) {

	copy_shell_runtime(work_dir);
	execute_cmd("/bin/mkdir -p %s/usr/local/lib", work_dir);
	execute_cmd("/bin/mkdir -p %s/usr/local/bin", work_dir);
	execute_cmd("/bin/cp /usr/local/lib/freebasic %s/usr/local/lib/", work_dir);
	execute_cmd("/bin/cp /usr/local/bin/fbc %s/", work_dir);
	execute_cmd("/bin/cp -a /lib32/* %s/lib/", work_dir);
}
void copy_mono_runtime(char *work_dir) {

	copy_shell_runtime(work_dir);
	execute_cmd("/bin/mkdir %s/usr", work_dir);
	execute_cmd("/bin/mkdir %s/proc", work_dir);
	execute_cmd("/bin/mkdir -p %s/usr/lib/mono/2.0", work_dir);
	execute_cmd("/bin/cp -a /usr/lib/mono %s/usr/lib/", work_dir);
	execute_cmd("/bin/mkdir -p %s/usr/lib64/mono/2.0", work_dir);
	execute_cmd("/bin/cp -a /usr/lib64/mono %s/usr/lib64/", work_dir);

	execute_cmd("/bin/cp /usr/lib/libgthread* %s/usr/lib/", work_dir);

	execute_cmd("/bin/mount -o bind /proc %s/proc", work_dir);
	execute_cmd("/bin/mount -o remount,ro %s/proc", work_dir);
	execute_cmd("/bin/cp /usr/bin/mono* %s/", work_dir);

	execute_cmd("/bin/cp /usr/lib/libgthread* %s/usr/lib/", work_dir);
	execute_cmd("/bin/cp /lib/libglib* %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib/tls/i686/cmov/lib* %s/lib/tls/i686/cmov/",
	            work_dir);
	execute_cmd("/bin/cp /lib/libpcre* %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib/ld-linux* %s/lib/", work_dir);
#ifdef __x86_64__
	execute_cmd("/bin/cp /lib64/ld-linux* %s/lib64/", work_dir);
#endif
	execute_cmd("/bin/mkdir -p %s/home/judge", work_dir);
	execute_cmd("/bin/chown judge %s/home/judge", work_dir);
	execute_cmd("/bin/mkdir -p %s/etc", work_dir);
	execute_cmd("/bin/grep judge /etc/passwd>%s/etc/passwd", work_dir);
}
void copy_lua_runtime(char *work_dir) {

	copy_shell_runtime(work_dir);
	execute_cmd("/bin/mkdir -p %s/usr/local/lib", work_dir);
	execute_cmd("/bin/mkdir -p %s/usr/local/bin", work_dir);
	execute_cmd("/bin/cp /usr/bin/lua %s/", work_dir);
}
void copy_sql_runtime(char *work_dir) {

	copy_shell_runtime(work_dir);
	execute_cmd("/bin/cp /usr/bin/sqlite3 %s/", work_dir);
#ifdef __mips__
	execute_cmd("/bin/cp /lib64/libedit.so.0 %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib64/libm.so.6 %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib64/libdl.so.2 %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib64/libz.so.1 %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib64/libpthread.so.0 %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib64/libc.so.6 %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib64/libtinfo.so.6 %s/lib64/", work_dir);
#endif
#ifdef __i386__
	execute_cmd("/bin/cp /usr/lib/i386-linux-gnu/libsqlite3.so.0*   %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libreadline.so.6*   %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libc.so.6*  %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libpthread.so.0 %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libdl.so.2* %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libtinfo.so.5* %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libedit.so.0 %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libm.so.6* %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libz.so.1 %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libtinfo.so.6* %s/lib/", work_dir);
#endif
#ifdef __x86_64__
	execute_cmd("/bin/cp /usr/lib/x86_64-linux-gnu/libsqlite3.so.0   %s/lib/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libreadline.so.6   %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libc.so.6  %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libpthread.so.0 %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libdl.so.2 %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libtinfo.so.5 %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libedit.so.0 %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libm.so.6 %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libz.so.1 %s/lib64/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libtinfo.so.6 %s/lib64/", work_dir);
#endif
}
void copy_js_runtime(char *work_dir) {

	//copy_shell_runtime(work_dir);
	execute_cmd("mkdir -p %s/dev", work_dir);
	execute_cmd("/bin/mount -o bind /dev %s/dev", work_dir);
	execute_cmd("/bin/mount -o remount,ro %s/dev", work_dir);
	execute_cmd("/bin/mkdir -p %s/usr/lib %s/lib/i386-linux-gnu/ %s/lib64/", work_dir, work_dir, work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libz.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /usr/lib/i386-linux-gnu/libuv.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /usr/lib/i386-linux-gnu/libicui18n.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /usr/lib/i386-linux-gnu/libicuuc.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /usr/lib/i386-linux-gnu/libicudata.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libtinfo.so.*  %s/lib/i386-linux-gnu/", work_dir);

	execute_cmd("/bin/cp /usr/lib/i386-linux-gnu/libcares.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /usr/lib/libv8.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libssl.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libcrypto.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libdl.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/librt.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /usr/lib/i386-linux-gnu/libstdc++.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libpthread.so.*  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libc.so.6  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libm.so.6  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/i386-linux-gnu/libgcc_s.so.1  %s/lib/i386-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/ld-linux.so.*  %s/lib/", work_dir);

#ifdef __x86_64__
	execute_cmd("/bin/mkdir -p %s/usr/lib %s/lib/x86_64-linux-gnu/", work_dir, work_dir);

	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libz.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /usr/lib/x86_64-linux-gnu/libuv.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/librt.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libpthread.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libdl.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libssl.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libcrypto.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /usr/lib/x86_64-linux-gnu/libicui18n.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /usr/lib/x86_64-linux-gnu/libicuuc.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /usr/lib/x86_64-linux-gnu/libstdc++.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libm.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libgcc_s.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib/x86_64-linux-gnu/libc.so.* %s/lib/x86_64-linux-gnu/", work_dir);
	execute_cmd("/bin/cp /lib64/ld-linux-x86-64.so.* %s/lib64/", work_dir);
	execute_cmd("/bin/cp /usr/lib/x86_64-linux-gnu/libicudata.so.* %s/lib/x86_64-linux-gnu/", work_dir);
#endif
	execute_cmd("/bin/cp /usr/bin/nodejs %s/", work_dir);
}
void run_status(int &lang, char *work_dir, int &time_lmt, int &usedtime,
                int &mem_lmt) {
	nice(19);
	// now the user is "judger"
	chdir(work_dir);
	// open the files
	if(lang==18) {
		execute_cmd("/usr/bin/sqlite3 %s/data.db < %s/data.in", work_dir,work_dir);
		execute_cmd("/bin/chown judge %s/data.db", work_dir);
		freopen("Main.sql", "r", stdin);
	} else {
		freopen("data.in", "r", stdin);
	}
	freopen("user.out", "w", stdout);
	freopen("error.out", "a+", stderr);
	// trace me
	if (use_ptrace)
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	// run me
	if (lang != 3)
		chroot(work_dir);

	while (setgid(1536) != 0)
		sleep(1);
	while (setuid(1536) != 0)
		sleep(1);
	while (setresuid(1536, 1536, 1536) != 0)
		sleep(1);

	//      char java_p1[BUFFER_SIZE], java_p2[BUFFER_SIZE];
	// child
	// set the limit
	struct rlimit LIM; // time limit, file limit& memory limit
	// time limit
	
	LIM.rlim_cur = time_lmt / cpu_compensation + 1;
	
	LIM.rlim_max = LIM.rlim_cur;
	//if(DEBUG) printf("LIM_CPU=%d",(int)(LIM.rlim_cur));
	setrlimit(RLIMIT_CPU, &LIM);
	alarm(0);
	alarm(time_lmt * 5 / cpu_compensation);

	// file limit
	LIM.rlim_max = STD_F_LIM + STD_MB;
	LIM.rlim_cur = STD_F_LIM;
	setrlimit(RLIMIT_FSIZE, &LIM);
	// proc limit
	switch (lang) {
		case 17:
		case 9: //C#
			LIM.rlim_cur = LIM.rlim_max = 280;
			break;
		case 3: //java
		case 4: //ruby
			//case 6:  //python
		case 12:
		case 16:
			LIM.rlim_cur = LIM.rlim_max = 200;
			break;
		case 5: //bash
			LIM.rlim_cur = LIM.rlim_max = 3;
			break;
		default:
			LIM.rlim_cur = LIM.rlim_max = 1;
	}

	setrlimit(RLIMIT_NPROC, &LIM);

	// set the stack
	LIM.rlim_cur = STD_MB << 7;
	LIM.rlim_max = STD_MB << 7;
	setrlimit(RLIMIT_STACK, &LIM);
	// set the memory
	LIM.rlim_cur = STD_MB * mem_lmt / 2 * 3;
	LIM.rlim_max = STD_MB * mem_lmt * 2;
	if (lang < 3 || lang == 10 || lang == 13 || lang == 14 || lang == 17)
		setrlimit(RLIMIT_AS, &LIM);

	switch (lang) {
		case 0:
		case 1:
		case 2:
		case 10:
		case 11:
		case 13:
		case 14:
		case 17:
		case 19:
			execl("./Main", "./Main", (char *)NULL);
			break;
		case 3:
			sprintf(java_xmx, "-Xmx%dM", mem_lmt);
			//sprintf(java_xmx, "-XX:MaxPermSize=%dM", mem_lmt);

			execl("/usr/bin/java", "/usr/bin/java",java_xmx ,
			      "-Djava.security.manager",
			      "-Djava.security.policy=./java.policy", "Main", (char *) NULL);
			break;
		case 4:
			//system("/ruby Main.rb<data.in");
			execl("/ruby", "/ruby", "Main.rb", (char *)NULL);
			break;
		case 5: //bash
			execl("/bin/bash", "/bin/bash", "Main.sh", (char *)NULL);
			break;
		case 6: //Python
			if (!py2) {
				execl("/python2", "/python2", "Main.py", (char *)NULL);
			} else {
				execl("/python3", "/python3", "Main.py", (char *)NULL);
			}
			break;
		case 7: //php
			execl("/php", "/php", "Main.php", (char *)NULL);
			break;
		case 8: //perl
			execl("/perl", "/perl", "Main.pl", (char *)NULL);
			break;
		case 9: //Mono C#
			execl("/mono", "/mono", "--debug", "Main.exe", (char *)NULL);
			break;
		case 12: //guile
			execl("/guile", "/guile", "Main.scm", (char *)NULL);
			break;
		case 15: //guile
			execl("/lua", "/lua", "Main", (char *)NULL);
			break;
		case 16: //Node.js
			execl("/nodejs", "/nodejs", "Main.js", (char *)NULL);
			break;
		case 18: //sqlite3
			execl("/sqlite3", "/sqlite3", "data.db", (char *)NULL);
			break;
	}
	//sleep(1);
	fflush(stderr);
	exit(0);
}
int fix_python_mis_judge(char *work_dir, int &ACflg, int &topmemory,
                         int mem_lmt) {
	int comp_res = OJ_AC;

	comp_res = execute_cmd(
	               "/bin/grep 'MemoryError'  %s/error.out", work_dir);

	if (!comp_res) {
		printf("Python need more Memory!");
		ACflg = OJ_ML;
		topmemory = mem_lmt * STD_MB;
	}

	return comp_res;
}

int fix_java_mis_judge(char *work_dir, int &ACflg, int &topmemory,
                       int mem_lmt) {
	int comp_res = OJ_AC;
	execute_cmd("chmod 700 %s/error.out", work_dir);
	if (DEBUG)
		execute_cmd("cat %s/error.out", work_dir);
	comp_res = execute_cmd("/bin/grep 'Exception'  %s/error.out", work_dir);
	if (!comp_res) {
		printf("Exception reported\n");
		ACflg = OJ_RE;
	}
	execute_cmd("cat %s/error.out", work_dir);

	comp_res = execute_cmd(
	               "/bin/grep 'java.lang.OutOfMemoryError'  %s/error.out", work_dir);

	if (!comp_res) {
		printf("JVM need more Memory!");
		ACflg = OJ_ML;
		topmemory = mem_lmt * STD_MB;
	}

	if (!comp_res) {
		printf("JVM need more Memory or Threads!");
		ACflg = OJ_ML;
		topmemory = mem_lmt * STD_MB;
	}
	comp_res = execute_cmd("/bin/grep 'Could not create'  %s/error.out",
	                       work_dir);
	if (!comp_res) {
		printf("jvm need more resource,tweak -Xmx(OJ_JAVA_BONUS) Settings");
		ACflg = OJ_RE;
		//topmemory=0;
	}
	return comp_res;
}
int special_judge(char *oj_home, int problem_id, char *infile, char *outfile,
                  char *userfile) {

	pid_t pid;
	printf("pid=%d\n", problem_id);
	pid = fork();
	int ret = 0;
	if (pid == 0) {

		while (setgid(1536) != 0)
			sleep(1);
		while (setuid(1536) != 0)
			sleep(1);
		while (setresuid(1536, 1536, 1536) != 0)
			sleep(1);

		struct rlimit LIM; // time limit, file limit& memory limit

		LIM.rlim_cur = 5;
		LIM.rlim_max = LIM.rlim_cur;
		setrlimit(RLIMIT_CPU, &LIM);
		alarm(0);
		alarm(10);

		// file limit
		LIM.rlim_max = STD_F_LIM + STD_MB;
		LIM.rlim_cur = STD_F_LIM;
		setrlimit(RLIMIT_FSIZE, &LIM);

		ret = execute_cmd("%s/data/%d/spj '%s' '%s' %s", oj_home, problem_id,
		                  infile, outfile, userfile);
		if (DEBUG)
			printf("spj1=%d\n", ret);
		if (ret)
			exit(1);
		else
			exit(0);
	} else {
		int status;

		waitpid(pid, &status, 0);
		ret = WEXITSTATUS(status);
		if (DEBUG)
			printf("spj2=%d\n", ret);
	}
	return ret;
}

void judge_status(int &ACflg, int &tasktime, int time_lmt, int isspj,
                  int p_id, char *infile, char *outfile, char *userfile, int &PEflg,
                  int lang, char *work_dir, int &topmemory, int mem_lmt,
                  int status_id) {
	//usedtime-=1000;
	int comp_res;

    if (ACflg == OJ_AC && tasktime > time_lmt * 1000 )
		ACflg = OJ_TL;
	if (topmemory > mem_lmt * STD_MB)
		ACflg = OJ_ML; //issues79
	// compare

//	printf("1111112111111 | %d\n",ACflg);

	if (ACflg == OJ_AC) {
		if (isspj) {
			comp_res = special_judge(oj_home, p_id, infile, outfile, userfile);

			if (comp_res == 0)
				comp_res = OJ_AC;
			else {
				if (DEBUG)
					printf("fail test %s\n", infile);
				comp_res = OJ_WA;
			}
		} else {
			comp_res = compare(outfile, userfile);
		}
//		printf("1111111111111 | %d\n",comp_res);
		if (comp_res == OJ_WA) {
			ACflg = OJ_WA;
			if (DEBUG)
				printf("fail test %s\n", infile);
		} else if (comp_res == OJ_PE)
			PEflg = OJ_PE;
		ACflg = comp_res;
	}
	//jvm popup messages, if don't consider them will get miss-WrongAnswer
	if (lang == 3) {
		comp_res = fix_java_mis_judge(work_dir, ACflg, topmemory, mem_lmt);
	}
	if (lang == 6) {
		comp_res = fix_python_mis_judge(work_dir, ACflg, topmemory, mem_lmt);
	}
}

int get_page_fault_mem(struct rusage &ruse, pid_t &pidApp) {
	//java use pagefault
	int m_vmpeak, m_vmdata, m_minflt;
	m_minflt = ruse.ru_minflt * getpagesize();
	if (0 && DEBUG) {
		m_vmpeak = get_proc_status(pidApp, "VmPeak:");
		m_vmdata = get_proc_status(pidApp, "VmData:");
		printf("VmPeak:%d KB VmData:%d KB minflt:%d KB\n", m_vmpeak, m_vmdata,
		       m_minflt >> 10);
	}
	return m_minflt;
}
void print_runtimeerror(char *err) {
	FILE *ferr = fopen("error.out", "a+");
	fprintf(ferr, "Runtime Error:%s\n", err);
	fclose(ferr);
}

void watch_status(pid_t pidApp, char *infile, int &ACflg, int isspj,
                  char *userfile, char *outfile, int status_id, int lang,
                  int &topmemory, int mem_lmt, int &usedtime, int time_lmt, int &p_id,
                  int &PEflg, char *work_dir) {
	// parent
	int tempmemory = 0;

	if (DEBUG)
		printf("pid=%d judging %s\n", pidApp, infile);

	int status, sig, exitcode;
	struct user_regs_struct reg;
	struct rusage ruse;
	int first = true;
	while (1) {
		// check the usage

		wait4(pidApp, &status, __WALL, &ruse);
		if (first) {
			//
			ptrace(PTRACE_SETOPTIONS, pidApp, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT
			       //	|PTRACE_O_EXITKILL
			       //	|PTRACE_O_TRACECLONE
			       //	|PTRACE_O_TRACEFORK
			       //	|PTRACE_O_TRACEVFORK
			      );
		}

		//jvm gc ask VM before need,so used kernel page fault times and page size
		if (lang == 3 || lang == 7 || lang == 9 || lang == 13 || lang == 14 || lang == 16 || lang == 17) {
			tempmemory = get_page_fault_mem(ruse, pidApp);
		} else {
			//other use VmPeak
			tempmemory = get_proc_status(pidApp, "VmPeak:") << 10;
		}
		if (tempmemory > topmemory)
			topmemory = tempmemory;
		if (topmemory > mem_lmt * STD_MB) {
			if (DEBUG)
				printf("out of memory %d\n", topmemory);
			if (ACflg == OJ_AC)
				ACflg = OJ_ML;
			ptrace(PTRACE_KILL, pidApp, NULL, NULL);
			break;
		}
		//sig = status >> 8;/*status >> 8 EXITCODE*/

		if (WIFEXITED(status))
			break;

		if (!isspj && get_file_size(userfile) > get_file_size(outfile) * 2 + 1024) {
			ACflg = OJ_OL;
			ptrace(PTRACE_KILL, pidApp, NULL, NULL);
			break;
		}

		exitcode = WEXITSTATUS(status);
		/*exitcode == 5 waiting for next CPU allocation          * ruby using system to run,exit 17 ok
		 *  Runtime Error:Unknown signal xxx need be added here
		         */
		if ((lang >= 3 && exitcode == 17) || exitcode == 0x05 || exitcode == 0 || exitcode == 133)
			//go on and on
			;
		else {

			if (DEBUG) {
				printf("status>>8=%d\n", exitcode);
			}
			//psignal(exitcode, NULL);

			if (ACflg == OJ_AC) {
				switch (exitcode) {
					case SIGCHLD:
					case SIGALRM:
						alarm(0);
						if (DEBUG)
							printf("alarm:%d\n", time_lmt);
					case SIGKILL:
					case SIGXCPU:
						ACflg = OJ_TL;
						usedtime = time_lmt * 1000;
						if (DEBUG)
							printf("TLE:%d\n", usedtime);
						break;
					case SIGXFSZ:
						ACflg = OJ_OL;
						break;
					default:
						ACflg = OJ_RE;
				}
				print_runtimeerror(strsignal(exitcode));
			}
			ptrace(PTRACE_KILL, pidApp, NULL, NULL);

			break;
		}
		if (WIFSIGNALED(status)) {
			/*  WIFSIGNALED: if the process is terminated by signal
			 *
			 *  psignal(int sig, char *s)，like perror(char *s)，print out s, with error msg from system of sig
			 * sig = 5 means Trace/breakpoint trap
			 * sig = 11 means Segmentation fault
			 * sig = 25 means File size limit exceeded
			 */
			sig = WTERMSIG(status);

			if (DEBUG) {
				printf("WTERMSIG=%d\n", sig);
				psignal(sig, NULL);
			}
			if (ACflg == OJ_AC) {
				switch (sig) {
					case SIGCHLD:
					case SIGALRM:
						alarm(0);
					case SIGKILL:
					case SIGXCPU:
						ACflg = OJ_TL;
						break;
					case SIGXFSZ:
						ACflg = OJ_OL;
						break;

					default:
						ACflg = OJ_RE;
				}
				print_runtimeerror(strsignal(sig));
			}
			break;
		}
		/*     comment from http://www.felix021.com/blog/read.php?1662

		 WIFSTOPPED: return true if the process is paused or stopped while ptrace is watching on it
		 WSTOPSIG: get the signal if it was stopped by signal
		 */

		// check the system calls
		ptrace(PTRACE_GETREGS, pidApp, NULL, &reg);
#ifdef __mips__
//		if(exitcode!=5&&exitcode!=133){
		//https://github.com/strace/strace/blob/master/linux/mips/syscallent-n32.h#L344
		if((unsigned int)reg.REG_SYSCALL<6500) {
#endif
			call_id = ((unsigned int)reg.REG_SYSCALL) % call_array_size;
			if (record_call) {
				printf("new call id:%d\n",call_id);
				call_counter[call_id]++;
				printf("call %d: %d\n",call_id,call_counter[call_id]);
			} else if (call_counter[call_id]) {
				call_counter[call_id]--;
			} else {
				//do not limit JVM syscall for using different JVM
				ACflg = OJ_RE;
				char error[BUFFER_SIZE];
				sprintf(error,
				        "[ERROR] A Not allowed system call: runid:%d CALLID:%u [%u]\n"
				        " TO FIX THIS , ask admin to add the CALLID into corresponding LANG_XXV[] located at okcalls32/64.h ,\n"
				        "and recompile judge_client. \n"
				        "if you are admin and you don't know what to do ,\n"
				        "chinese explaination can be found on https://zhuanlan.zhihu.com/p/24498599\n",
				        status_id, call_id,exitcode);

				write_log(error);
				print_runtimeerror(error);
				ptrace(PTRACE_KILL, pidApp, NULL, NULL);
			}
#ifdef __mips__
		}
//		}
#endif
		ptrace(PTRACE_SYSCALL, pidApp, NULL, NULL);
		first = false;
		//usleep(1);
	}
	usedtime += (ruse.ru_utime.tv_sec * 1000 + ruse.ru_utime.tv_usec / 1000) * cpu_compensation;
	usedtime += (ruse.ru_stime.tv_sec * 1000 + ruse.ru_stime.tv_usec / 1000) * cpu_compensation;

	//clean_session(pidApp);
}

void clean_workdir(char *work_dir) {
	umount(work_dir);
	if (DEBUG) {
		execute_cmd("/bin/rm -rf %s/log/* 2>/dev/null", work_dir);
		execute_cmd("mkdir %s/log/ 2>/dev/null", work_dir);
		execute_cmd("/bin/mv %s/* %s/log/ 2>/dev/null", work_dir, work_dir);
	} else {
		execute_cmd("mkdir %s/log/ 2>/dev/null", work_dir);
		execute_cmd("/bin/mv %s/* %s/log/ 2>/dev/null", work_dir, work_dir);
		execute_cmd("/bin/rm -rf %s/log/* 2>/dev/null", work_dir);
	}
}

void init_parameters(int argc, char **argv, int &status_id,
                     int &runner_id) {
	if (argc < 3) {
		fprintf(stderr, "Usage:%s status_id runner_id.\n", argv[0]);
		fprintf(stderr, "Multi:%s status_id runner_id judge_base_path.\n",
		        argv[0]);
		fprintf(stderr,
		        "Debug:%s status_id runner_id judge_base_path debug.\n",
		        argv[0]);
		exit(1);
	}
	DEBUG = (argc > 4);
	record_call = (argc > 5);
	if (argc > 5) {
		strcpy(LANG_NAME, argv[5]);
	}
	if (argc > 3)
		strcpy(oj_home, argv[3]);
	else
		strcpy(oj_home, "/home/judge");

	chdir(oj_home); // change the dir// init our work

	status_id = atoi(argv[1]);
	runner_id = atoi(argv[2]);
}
void mk_shm_workdir(char *work_dir) {
	char shm_path[BUFFER_SIZE];
	sprintf(shm_path, "/dev/shm/codeoj/%s", work_dir);
	execute_cmd("/bin/mkdir -p %s  2>/dev/null", shm_path);
	execute_cmd("/bin/ln -s %s %s/  2>/dev/null", shm_path, oj_home);
	execute_cmd("/bin/chown judge %s  2>/dev/null", shm_path);
	execute_cmd("chmod 755 %s  2>/dev/null", shm_path);
	//sim need a soft link in shm_dir to work correctly
	//sprintf(shm_path, "/dev/shm/codeoj/%s/", oj_home);
    //execute_cmd("/bin/ln -s %s/data %s  2>/dev/null", oj_home, shm_path);
}
int count_in_files(char *dirpath) {
	const char *cmd = "ls -l %s/*.in|wc -l";
	int ret = 0;
	FILE *fjobs = read_cmd_output(cmd, dirpath);
	fscanf(fjobs, "%d", &ret);
	pclose(fjobs);

	return ret;
}

void print_call_array() {
	printf("int LANG_%sV[256]={", LANG_NAME);
	int i = 0;
	for (i = 0; i < call_array_size; i++) {
		if (call_counter[i]) {
			printf("%d,", i);
		}
	}
	printf("0};\n");

	printf("int LANG_%sC[256]={", LANG_NAME);
	for (i = 0; i < call_array_size; i++) {
		if (call_counter[i]) {
			printf("HOJ_MAX_LIMIT,");
		}
	}
	printf("0};\n");
}


int main(int argc, char **argv) {

	char buf[BUFFER_SIZE];

	char work_dir[BUFFER_SIZE];
	//char cmd[BUFFER_SIZE];
	char user_id[BUFFER_SIZE];
	int status_id = 1000;
	int runner_id = 0;
	int p_id, time_lmt, mem_lmt, lang, isspj,cid=0;
	char time_space_table[BUFFER_SIZE*100];
	int time_space_index=0;

	bool custom_rule=false;
	FILE *rule;
	char rulefile[BUFFER_SIZE];
	char inputFile[BUFFER_SIZE];
	char outputFile[BUFFER_SIZE];
	char inputPrefix[BUFFER_SIZE];
	char inputSuffix[BUFFER_SIZE];
	char outputPrefix[BUFFER_SIZE];
	char outputSuffix[BUFFER_SIZE];
	char inputFileName[BUFFER_SIZE];
	char outputFileName[BUFFER_SIZE];
	int taskCount=0;
	int taskScore=0;
	char taskType[BUFFER_SIZE];
	char taskCase[BUFFER_SIZE];
	char extraFiles[BUFFER_SIZE];
	char taskScoreName[BUFFER_SIZE];
	char taskTypeName[BUFFER_SIZE];
	char taskCaseName[BUFFER_SIZE];

	init_parameters(argc, argv, status_id, runner_id);

	init_mysql_conf();

	if (!init_mysql_conn()) {
		exit(0); //exit if mysql is down
	}

	//set work directory to start running & judging
	sprintf(work_dir, "%s/run%s/", oj_home, argv[2]);
	
	clean_workdir(work_dir);
	if (shm_run)
		mk_shm_workdir(work_dir);
	chdir(work_dir);

	get_status_info(status_id, p_id, user_id, lang,cid);
	//get the limit

	if (p_id == 0) {
		time_lmt = 5;
		mem_lmt = 128;
		isspj = 0;
	} else {
		get_problem_info(p_id, time_lmt, mem_lmt, isspj);
	}

//	printf("%d------%d----%d\n",time_lmt,mem_lmt,isspj);

	//copy source file

	get_status(status_id, work_dir, lang);


	//java is lucky
	if (lang >= 3 && lang != 10 && lang != 13 && lang != 14 && lang != 17) {
		//ObjectivC Clang Clang++ Go not VM or Script
		// the limit for java
		time_lmt = time_lmt + java_time_bonus;
		mem_lmt = mem_lmt + java_memory_bonus;
		// copy java.policy
		if (lang == 3) {
			execute_cmd("/bin/cp %s/etc/java0.policy %s/java.policy", oj_home, work_dir);
			execute_cmd("chmod 755 %s/java.policy", work_dir);
			execute_cmd("chown judge %s/java.policy", work_dir);
		}
	}

	//never bigger than judged set value;
	if (time_lmt > 300 || time_lmt < 1)
		time_lmt = 300;
	if (mem_lmt > 1024 || mem_lmt < 1)
        mem_lmt = 1024;

	if (DEBUG)
		printf("time: %d mem: %d\n", time_lmt, mem_lmt);

	sprintf(rulefile, "%s/data/%d/rule.conf", oj_home,p_id);
//	printf("%s\n",rulefile);

	rule = fopen(rulefile, "re");
	if (rule != NULL) {
		custom_rule=true;
		sprintf(extraFiles,"extraFiles_%s",lang_ext[lang]);

		while (fgets(buf, BUFFER_SIZE - 1, rule)) {
			const char *d = "#";
			char *ts;

			if(read_buf(buf, "inputFile", inputFile)) {
				ts = strtok(inputFile,d);
				memcpy(inputPrefix, ts, strlen(ts));
				ts=strtok(NULL,d);
				memcpy(inputSuffix, ts, strlen(ts));
			}

			if(read_buf(buf, "outputFile", outputFile)) {
				ts = strtok(outputFile,d);
				memcpy(outputPrefix, ts, strlen(ts));
				ts=strtok(NULL,d);
				memcpy(outputSuffix, ts, strlen(ts));
			}
			read_buf(buf, extraFiles, extraFiles);
			read_int(buf, "taskCount", &taskCount);

		}

		//fclose(fp);
	}
	if(custom_rule) {

		const char *d = " ,";
		char *extraFile;
		extraFile = strtok(extraFiles,d);
		while(extraFile) {
//			printf("%s\n",extraFile);
			prepare_extra_files(extraFile,p_id,work_dir);
			extraFile=strtok(NULL,d);
		}

	}

	clean_task(status_id);

	// compile
	//      printf("%s\n",cmd);
	// set the result to compiling
	int Compile_OK;

	Compile_OK = compile(lang, work_dir);
	addceinfo(status_id);
	if (Compile_OK != 0) {
		update_status(status_id, OJ_CE, -1, -1, 0);

		update_problem(p_id,cid);

		mysql_close(conn);

		clean_workdir(work_dir);
		write_log("compile error");
		exit(0);
	} else {
		update_status(status_id, OJ_RI, -1, -1, 0);
		umount(work_dir);
	}
	//exit(0);
	// run
	char fullpath[BUFFER_SIZE];
	char infile[BUFFER_SIZE];
	char outfile[BUFFER_SIZE];
	char userfile[BUFFER_SIZE];
	sprintf(fullpath, "%s/data/%d", oj_home, p_id); // the fullpath of data dir

	// open DIRs

	DIR *dp;
	dirent *dirp;

	// using http to get remote test data files

	if (p_id > 0 && (dp = opendir(fullpath)) == NULL) {

		update_status(status_id, OJ_JF, -1, -1, 0);

		write_log("No such dir:%s!\n", fullpath);

		mysql_close(conn);

		exit(-1);
	}

	int ACflg, PEflg;
	ACflg = PEflg = OJ_AC;

	int usedtime = 0, topmemory = 0;

	//create chroot for ruby bash python
	if (lang == 4)
		copy_ruby_runtime(work_dir);
	if (lang == 5)
		copy_bash_runtime(work_dir);
	if (lang == 6)
		copy_python_runtime(work_dir);
	if (lang == 7)
		copy_php_runtime(work_dir);
	if (lang == 8)
		copy_perl_runtime(work_dir);
	if (lang == 9)
		copy_mono_runtime(work_dir);
	if (lang == 10)
		copy_objc_runtime(work_dir);
	if (lang == 11)
		copy_freebasic_runtime(work_dir);
	if (lang == 12)
		copy_guile_runtime(work_dir);
	if (lang == 15)
		copy_lua_runtime(work_dir);
	if (lang == 16)
		copy_js_runtime(work_dir);
	if (lang == 18)
		copy_sql_runtime(work_dir);
	// read files and run
	// read files and run
	// read files and run

	int score = 0;
	int sumTaskScore = 0;
	int finalACflg = ACflg;

//	if (p_id == 0) {
//		//custom input running
//		printf("running a custom input...\n");
//		get_custominput(status_id, work_dir);
//		init_syscalls_limits(lang);
//		pid_t pidApp = fork();
//
//		if (pidApp == 0) {
//			run_status(lang, work_dir, time_lmt, usedtime, mem_lmt);
//		} else {
//			watch_status(pidApp, infile, ACflg, isspj, userfile, outfile,
//			             status_id, lang, topmemory, mem_lmt, usedtime, time_lmt,
//			             p_id, PEflg, work_dir);
//		}
//		if (finalACflg == OJ_TL) {
//			usedtime = time_lmt;
//		}
//		if (ACflg == OJ_RE) {
//			if (DEBUG)
//				printf("add RE info of %d..... \n", status_id);
//			addreinfo(status_id);
//		} else {
//			addcustomout(status_id);
//		}
//		update_status(status_id, OJ_TR, usedtime, topmemory >> 10, 0, 0, 0);
//		clean_workdir(work_dir);
//		exit(0);
//	}

	if(custom_rule) {
		taskCount=taskCount;
		int maxTopmemory=0;
		int sumTime=0;
		for(int i=0; i<taskCount; i++) {
//			printf("----------------------%d\n",i);
			rule = fopen(rulefile, "re");
			while (fgets(buf, BUFFER_SIZE - 1, rule)) {
				sprintf(taskScoreName,"task_%d_score",i);
				sprintf(taskTypeName,"task_%d_type",i);
				sprintf(taskCaseName,"task_%d_cases",i);

				read_int(buf, taskScoreName, &taskScore);
				read_buf(buf, taskTypeName, taskType);
				read_buf(buf, taskCaseName, taskCase);
			}
			sumTaskScore+=taskScore;

			const char *d = " ,";
			char *caseName;
			caseName = strtok(taskCase,d);

			int caseScore=0;

			int caseCount=0;
			int acCount=0;

			ACflg=OJ_AC;
			while(caseName) {
				int tasktime=0;
				caseCount++;
				sprintf(inputFileName, "%s%s%s", inputPrefix, caseName, inputSuffix);
				sprintf(outputFileName, "%s%s%s", outputPrefix, caseName, outputSuffix);

				cp_data_files(work_dir,inputFileName,outputFileName,
				              p_id,infile,outfile,userfile,runner_id);

				init_syscalls_limits(lang);

				pid_t pidApp = fork();

				if (pidApp == 0) {
					run_status(lang, work_dir, time_lmt, tasktime, mem_lmt);
				} else {
					watch_status(pidApp, infile, ACflg, isspj, userfile, outfile,
					             status_id, lang, topmemory, mem_lmt, tasktime, time_lmt,
					             p_id, PEflg, work_dir);

//					printf("********************%d\n",tasktime);
//					printf("%s: mem=%d time=%d\n",infile+strlen(oj_home)+5,topmemory,usedtime);

					time_space_index+=sprintf(time_space_table+time_space_index,"%s: mem=%dk time=%dms\n",infile+strlen(oj_home)+5,topmemory/1024,tasktime);

					judge_status(ACflg, tasktime, time_lmt, isspj, p_id, infile,
					             outfile, userfile, PEflg, lang, work_dir, topmemory,
					             mem_lmt, status_id);
//					printf("********************%d\n",tasktime);

					if(ACflg==OJ_WA) {
						add_task_info(status_id,i,ACflg,tasktime,topmemory >> 10,"diff.out");
					} else {
						add_task_info(status_id,i,ACflg,tasktime,topmemory >> 10,"error.out");
					}

					if(topmemory>maxTopmemory) {
						maxTopmemory=topmemory;
					}
					sumTime+=tasktime;

					//clean_session(pidApp);
				}

				if(ACflg==OJ_AC) {
					acCount++;
				}
				if (finalACflg < ACflg) {
					finalACflg = ACflg;
				}
				caseName=strtok(NULL,d);
			}
//			printf("%d %d %d\n",taskScore,acCount,caseCount);
			if(!strcmp(taskType,"sum")) {
				caseScore+=(taskScore*acCount/caseCount);
			} else if(!strcmp(taskType,"min")) {
				caseScore+=(acCount==caseCount?taskScore:0);
			} else {
				caseScore+=(taskScore*acCount/caseCount)*acCount/caseCount;
			}
//			printf("---------------%d\n",caseScore);
			score+=caseScore;
		}
//		printf("%d %d %d %d\n",finalACflg,sumTime,maxTopmemory,score);
		usedtime= sumTime;
		topmemory=maxTopmemory;
	} else {
		sumTaskScore=100;
		taskCount=0;
		int maxTopmemory=0;
		int sumTime=0;
		int acCount=0;

		for (; (dirp = readdir(dp)) != NULL;) {
		int tasktime=0;

			int namelen = isInFile(dirp->d_name); // check if the file is *.in or not
			if (namelen == 0)
				continue;

			prepare_files(dirp->d_name, namelen, infile, p_id, work_dir, outfile,
			              userfile, runner_id);

			if (access(outfile, 0) == -1) {
				//out file does not exist
				char error[BUFFER_SIZE];
				sprintf(error, "missing out file %s, report to system administrator!\n", outfile);
				print_runtimeerror(error);
				ACflg = OJ_RE;
			}
			init_syscalls_limits(lang);

			pid_t pidApp = fork();

			if (pidApp == 0) {
				run_status(lang, work_dir, time_lmt, tasktime, mem_lmt);
			} else {

				watch_status(pidApp, infile, ACflg, isspj, userfile, outfile,
				             status_id, lang, topmemory, mem_lmt, tasktime, time_lmt,
				             p_id, PEflg, work_dir);
//				printf("%s: mem=%d time=%d\n",infile+strlen(oj_home)+5,topmemory,usedtime);
				time_space_index+=sprintf(time_space_table+time_space_index,"%s: mem=%dk time=%dms\n",infile+strlen(oj_home)+5,topmemory/1024,tasktime);

				judge_status(ACflg, tasktime, time_lmt, isspj, p_id, infile,
				             outfile, userfile, PEflg, lang, work_dir, topmemory,
				             mem_lmt, status_id);

                if(ACflg==OJ_TL){
                    tasktime=time_lmt*1000;   
                }
				if(ACflg==OJ_WA) {
					add_task_info(status_id,taskCount,ACflg,tasktime,topmemory >> 10,"diff.out");
				} else {
					add_task_info(status_id,taskCount,ACflg,tasktime,topmemory >> 10,"error.out");
				}

				if(topmemory>maxTopmemory) {
					maxTopmemory=topmemory;
				}
				sumTime+=tasktime;
				//clean_session(pidApp);
			}
//			printf("------%d\n",ACflg);
			if(ACflg==OJ_AC) {
				acCount++;
			}
			if (finalACflg < ACflg) {
				finalACflg = ACflg;
			}

			taskCount++;
			ACflg = OJ_AC;
		}
		if(!taskCount){
			score=0;
			usedtime=-1;
			topmemory=-1;
			finalACflg=OJ_JF;
		}else{
			score=100*acCount/taskCount;
			usedtime= sumTime;
			topmemory=maxTopmemory;
		}
	}
/*
	if (ACflg == OJ_AC && PEflg == OJ_PE)
		ACflg = OJ_PE;
*/
	score=score*100/sumTaskScore;

	update_status(status_id, finalACflg, usedtime, topmemory >> 10,  score);

	update_problem(p_id,cid);
	clean_workdir(work_dir);

	if (DEBUG)
		write_log("result=%d", finalACflg);

	mysql_close(conn);

	if (record_call) {
		print_call_array();
	}
	closedir(dp);
	return 0;
}