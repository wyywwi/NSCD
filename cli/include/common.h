#ifndef _COMMON_APP_H
#define _COMMON_APP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>

// ---- APP 与 Kernel 通用协议 ------
#define MAX_RULENAME_LEN 11
#define MAX_FILENAME_LEN 127

#define REQ_GETAllIPRules 1
#define REQ_ADDIPRule 2
#define REQ_CHANGEIPRule 16
#define REQ_DELIPRule 3
#define REQ_SETAction 4 
#define REQ_GETAllIPLogs 5
#define REQ_GETAllConns 6
#define REQ_ADDNATRule 7
#define REQ_DELNATRule 8
#define REQ_GETNATRules 9
#define REQ_SAVEIPRule 10
#define REQ_LOADIPRule 11
#define REQ_CLEARIPRule 12

#define RSP_Only_Head 20
#define RSP_MSG 21
#define RSP_IPRules 22  // body为IPRule[]
#define RSP_IPLogs 23   // body为IPlog[]
#define RSP_NATRules 24 // body为NATRecord[]
#define RSP_ConnLogs 25 // body为ConnLog[]

struct IPRule {
    char name[MAX_RULENAME_LEN+1];
    unsigned int saddr;
    unsigned int smask;
    unsigned int daddr;
    unsigned int dmask;
    unsigned int sport; // 源端口范围 高2字节为最小 低2字节为最大
    unsigned int dport; // 目的端口范围 同上
    u_int8_t protocol;
    unsigned int action;
    unsigned int log;
    struct IPRule* nx;
};

struct IPLog {
    long tm;
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    u_int8_t protocol;
    unsigned int len;
    unsigned int action;
    struct IPLog* nx;
};

struct NATRecord { // NAT 记录 or 规则(源IP端口转换)
    unsigned int saddr; // 记录：原始IP | 规则：原始源IP
    unsigned int smask; // 记录：无作用  | 规则：原始源IP掩码
    unsigned int daddr; // 记录：转换后的IP | 规则：NAT 源IP

    unsigned short sport; // 记录：原始端口 | 规则：最小端口范围
    unsigned short dport; // 记录：转换后的端口 | 规则：最大端口范围
    unsigned short nowPort; // 记录：当前使用端口 | 规则：无作用
    struct NATRecord* nx;
};

struct ConnLog {
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    u_int8_t protocol;
    int natType;
    struct NATRecord nat; // NAT记录
};

struct APPRequest {
    unsigned int tp;
    char ruleName[MAX_RULENAME_LEN+1];
    int num;
    union {
        struct IPRule ipRule;
        struct NATRecord natRule;
        unsigned int defaultAction;
        unsigned int num;
        char filename[MAX_FILENAME_LEN+1];
    } msg;
};

struct nfMessageHeader {
    unsigned int bodyTp;
    unsigned int arrayLen;
};

#define NAT_TYPE_NO 0
#define NAT_TYPE_SRC 1
#define NAT_TYPE_DEST 2

// ----- 上层应用专用 ------
#define uint8_t unsigned char
#define NETLINK_MYFW 17
#define MAX_PAYLOAD (1024 * 256)

#define ERROR_CODE_EXIT -1
#define ERROR_CODE_EXCHANGE -2 // 与内核交换信息失败
#define ERROR_CODE_WRONG_IP -11 // 错误的IP格式
#define ERROR_CODE_NO_SUCH_RULE -12
#define ERROR_CODE_INVALID -13

/** 
 * @brief 内核回应包
 */
struct nfMessage {
    int code; // <0 代表请求失败，失败码; >=0 代表body长度
    void *data; // 回应包指针，记得free
    struct nfMessageHeader *header; // 不要free；指向data中的头部
    void *body; // 不要free；指向data中的Body
};

/**
 * @brief 与内核交换数据
 * @param smsg: 发送的消息
 * @param slen: 发送消息的长度
 * @return nfMessage: 接收到的回应，其中data字段记得free
 */
struct nfMessage exchangeMsgK(void *smsg, unsigned int slen);

// ----- 与内核交互函数 -----

struct nfMessage addFilterRule(char *after,char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned int log,unsigned int action); // 新增一条过滤规则，其中，sport/dport为端口范围：高2字节为最小 低2字节为最大
struct nfMessage changeFilterRule(int key,char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned int log,unsigned int action); // 修改一条过滤规则，其中，sport/dport为端口范围：高2字节为最小 低2字节为最大
struct nfMessage del_rule(char *name);
struct nfMessage get_all_rules(void);
struct nfMessage add_nat_rule(char *sip,char *natIP,unsigned short minport,unsigned short maxport);
struct nfMessage del_nat_rule(int num);
struct nfMessage get_all_nat_rules(void);
struct nfMessage set_default_action(unsigned int action);
struct nfMessage get_logs(unsigned int num); // num=0时，获取所有日志
struct nfMessage get_connections(void);
struct nfMessage save_rules(const char* filename);
struct nfMessage load_rules(const char* filename);
struct nfMessage clear_rules(void);

// ----- 一些工具函数 ------

int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask);
int IPint2IPstr(unsigned int ip, unsigned int mask, char *ipStr);
int IPint2IPstrNoMask(unsigned int ip, char *ipStr);
int IPint2IPstrWithPort(unsigned int ip, unsigned short port, char *ipStr);
void printHeader(int col);
void printFooter(int col);
void printParser(int col);

#endif