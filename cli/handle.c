#include "common.h"

struct KernelResponse addFilterRule(char *after,char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned int log,unsigned int action) {
	struct APPRequest req;
    struct KernelResponse rsp;
	// form rule
	struct IPRule rule;
	if(IPstr2IPint(sip,&rule.saddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	if(IPstr2IPint(dip,&rule.daddr,&rule.dmask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	rule.saddr = rule.saddr;
	rule.daddr = rule.daddr;
	rule.sport = sport;
	rule.dport = dport;
	rule.log = log;
	rule.action = action;
	rule.protocol = proto;
	strncpy(rule.name, name, MAX_RULENAME_LEN);
	// form req
	req.tp = REQ_ADDIPRule;
	req.ruleName[0]=0;
	strncpy(req.ruleName, after, MAX_RULENAME_LEN);
	req.msg.ipRule = rule;
	// exchange
	return exchangeMsgK(&req, sizeof(req));
}

struct KernelResponse changeFilterRule(int key, char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned int log,unsigned int action) {
	struct APPRequest req;
    struct KernelResponse rsp;
	// form rule
	struct IPRule rule;
	if(strcmp(sip, "-1") == 0)
		rule.saddr=0, rule.smask=0;
	else if(IPstr2IPint(sip,&rule.saddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	if(strcmp(dip, "-1") == 0)
		rule.daddr=0, rule.dmask=0;
	else if(IPstr2IPint(dip,&rule.daddr,&rule.dmask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	rule.sport = sport;
	rule.dport = dport;
	rule.log = log;
	rule.action = action;
	rule.protocol = proto;
	strncpy(rule.name, name, MAX_RULENAME_LEN);
	// form req
	req.tp = REQ_CHANGEIPRule;
	req.num = key;
	req.msg.ipRule = rule;
	// exchange
	return exchangeMsgK(&req, sizeof(req));
}

struct KernelResponse delFilterRule(char *name) {
	struct APPRequest req;
	// form request
	req.tp = REQ_DELIPRule;
	strncpy(req.ruleName, name, MAX_RULENAME_LEN);
	// exchange
	return exchangeMsgK(&req, sizeof(req));
}

struct KernelResponse getAllFilterRules(void) {
	struct APPRequest req;
	// exchange msg
	req.tp = REQ_GETAllIPRules;
	return exchangeMsgK(&req, sizeof(req));
}

struct KernelResponse addNATRule(char *sip,char *natIP,unsigned short minport,unsigned short maxport) {
	struct APPRequest req;
	struct KernelResponse rsp;
	// form rule
	struct NATRecord rule;
	if(IPstr2IPint(natIP,&rule.daddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	if(IPstr2IPint(sip,&rule.saddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	rule.sport = minport;
	rule.dport = maxport;
	// form req
	req.tp = REQ_ADDNATRule;
	req.msg.natRule = rule;
	// exchange
	return exchangeMsgK(&req, sizeof(req));
}

struct KernelResponse delNATRule(int num) {
	struct APPRequest req;
	struct KernelResponse rsp;
	if(num < 0) {
		rsp.code = ERROR_CODE_NO_SUCH_RULE;
		return rsp;
	}
	req.tp = REQ_DELNATRule;
	req.msg.num = num;
	// exchange
	return exchangeMsgK(&req, sizeof(req));
}

struct KernelResponse getAllNATRules(void) {
	struct APPRequest req;
	// exchange msg
	req.tp = REQ_GETNATRules;
	return exchangeMsgK(&req, sizeof(req));
}

struct KernelResponse setDefaultAction(unsigned int action) {
	struct APPRequest req;
	// form request
	req.tp = REQ_SETAction;
	req.msg.defaultAction = action;
	// exchange
	return exchangeMsgK(&req, sizeof(req));
}

struct KernelResponse getLogs(unsigned int num) {
	struct APPRequest req;
	// exchange msg
	req.msg.num = num;
	req.tp = REQ_GETAllIPLogs;
	return exchangeMsgK(&req, sizeof(req));
}

struct KernelResponse getAllConns(void) {
	struct APPRequest req;
	// exchange msg
	req.tp = REQ_GETAllConns;
	return exchangeMsgK(&req, sizeof(req));
}

int isValidFilename(const char* filename) {
    // 检查 NULL 指针和长度限制
    if (filename == NULL) return 0;
    size_t len = strlen(filename);
    if (len == 0 || len > MAX_FILENAME_LEN) return 0;

    // 必须以 '/' 开头，确保是绝对路径
    if (filename[0] != '/') return 0;

    // 防止目录遍历和路径中的多余的 "//"
    if (strstr(filename, "..") || strstr(filename, "//")) return 0;

    // 检查路径中是否包含特殊字符
    const char *illegal_chars = "*?<>|";
    for (size_t i = 0; i < len; ++i) {
        if (strchr(illegal_chars, filename[i])) return 0;
    }

    return 1; // 符合所有检查条件
}

struct KernelResponse saveRulesCommand(const char* filename) {
    struct APPRequest req;
    struct KernelResponse rsp;

    if (!isValidFilename(filename)) {
        printf("Error: Invalid or empty filename provided.\n");
        rsp.code = ERROR_CODE_INVALID;
        return rsp;
    }

    req.tp = REQ_SAVEIPRule;
    strncpy(req.msg.filename, filename, sizeof(req.msg.filename) - 1);
    req.msg.filename[sizeof(req.msg.filename) - 1] = '\0';

    rsp = exchangeMsgK(&req, sizeof(req));
    return rsp;
}

struct KernelResponse loadRulesCommand(const char* filename) {
    struct APPRequest req;
    struct KernelResponse rsp;

    if (!isValidFilename(filename)) {
        printf("Error: Invalid or empty filename provided.\n");
        rsp.code = ERROR_CODE_INVALID;
        return rsp;
    }

    req.tp = REQ_LOADIPRule;
    strncpy(req.msg.filename, filename, sizeof(req.msg.filename) - 1);
    req.msg.filename[sizeof(req.msg.filename) - 1] = '\0';

    rsp = exchangeMsgK(&req, sizeof(req));
    return rsp;
}