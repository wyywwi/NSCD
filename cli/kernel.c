#include "common.h"

int showRules(struct IPRule *rules, int len);
int showNATRules(struct NATRecord *rules, int len);
int showLogs(struct IPLog *logs, int len);
int showConns(struct ConnLog *logs, int len);

void dealResponseAtCmd(struct nfMessage rsp) {
	// 判断错误码
	switch (rsp.code) {
	case ERROR_CODE_EXIT:
		exit(0);
		break;
	case ERROR_CODE_NO_SUCH_RULE:
		printf("[Kernel Response] Rule not found.\n");
		return;
	case ERROR_CODE_WRONG_IP:
		printf("[Kernel Response] Incorrect IP format.\n");
		return;
	}
	if(rsp.code < 0 || rsp.data == NULL || rsp.header == NULL || rsp.body == NULL) 
		return;
	// 处理数据
	switch (rsp.header->bodyTp) {
	case RSP_Only_Head:
		if(rsp.header->arrayLen) printf("[Kernel Response] Delete %d rules.\n", rsp.header->arrayLen);
		else printf("[Kernel Response] No related rules found.\n");
		break;
	case RSP_MSG:
		printf("[Kernel Response] %s\n", (char*)rsp.body);
		break;
	case RSP_IPRules:
		showRules((struct IPRule*)rsp.body, rsp.header->arrayLen);
		break;
	case RSP_NATRules:
		showNATRules((struct NATRecord*)rsp.body, rsp.header->arrayLen);
		break;
	case RSP_IPLogs:
		showLogs((struct IPLog*)rsp.body, rsp.header->arrayLen);
		break;
	case RSP_ConnLogs:
		showConns((struct ConnLog*)rsp.body, rsp.header->arrayLen);
		break;
	}
	if(rsp.header->bodyTp != RSP_Only_Head && rsp.body != NULL) {
		free(rsp.data);
	}
}

void printLine(int len) {
	int i;
	for(i = 0; i < len; i++) {
		printf("-");
	}
	printf("\n");
}

int showOneRule(struct IPRule rule) {
    char saddr[25], daddr[25], sport[13], dport[13], proto[10], action[10], log[4];
    IPint2IPstr(rule.saddr, rule.smask, saddr);
    IPint2IPstr(rule.daddr, rule.dmask, daddr);

    // Format ports
    if(rule.sport == 0xFFFFu)
        strcpy(sport, "any");
    else if((rule.sport >> 16) == (rule.sport & 0xFFFFu))
        sprintf(sport, "%u", (rule.sport >> 16));
    else
        sprintf(sport, "%u~%u", (rule.sport >> 16), (rule.sport & 0xFFFFu));

    if(rule.dport == 0xFFFFu)
        strcpy(dport, "any");
    else if((rule.dport >> 16) == (rule.dport & 0xFFFFu))
        sprintf(dport, "%u", (rule.dport >> 16));
    else
        sprintf(dport, "%u~%u", (rule.dport >> 16), (rule.dport & 0xFFFFu));

    // Format action
    switch (rule.action) {
        case NF_ACCEPT: strcpy(action, "ACCEPT"); break;
        case NF_DROP: strcpy(action, "DROP"); break;
        default: strcpy(action, "OTHER"); break;
    }

    // Format protocol
    switch (rule.protocol) {
        case IPPROTO_TCP: strcpy(proto, "TCP"); break;
        case IPPROTO_UDP: strcpy(proto, "UDP"); break;
        case IPPROTO_ICMP: strcpy(proto, "ICMP"); break;
        case IPPROTO_IP: strcpy(proto, "IP"); break;
        default: strcpy(proto, "OTHER"); break;
    }

    // Format log
    strcpy(log, rule.log ? "YES" : "NO");

    // Print the formatted rule
	printParser(109);
    printf("| %-*s | %-18s | %-18s | %-11s | %-11s | %-8s | %-6s | %-3s |\n", MAX_RULENAME_LEN,
           rule.name, saddr, daddr, sport, dport, proto, action, log);
    return 0;
}

int showRules(struct IPRule *rules, int len) {
    if(len == 0) {
        printf("No rules now.\n");
        return 0;
    }
    int col = 109;  // Adjusted column width
    printHeader(col);
    printf("| %-*s | %-18s | %-18s | %-11s | %-11s | %-8s | %-6s | %-3s |\n", MAX_RULENAME_LEN,
           "Name", "Source IP", "Target IP", "Src Port", "Dst Port", "Protocol", "Action", "Log");
    for(int i = 0; i < len; i++) {
        showOneRule(rules[i]);
    }
    printFooter(col);
    return 0;
}

int showNATRules(struct NATRecord *rules, int len) {
    int col = 66;
    char saddr[25], daddr[25];
    if(len == 0) {
        printf("No NAT rules now.\n");
        return 0;
    }
    printHeader(col);
    printf("| seq | %18s |->| %-18s | %-13s |\n", "source ip", "NAT ip", "NAT port");
    for(int i = 0; i < len; i++) {
		printParser(col);
        IPint2IPstr(rules[i].saddr, rules[i].smask, saddr);
        IPint2IPstrNoMask(rules[i].daddr, daddr);
        printf("| %3d | %18s |->| %-18s | %-5u ~ %5u |\n", i, saddr, daddr, rules[i].sport, rules[i].dport);
    }
    printFooter(col);
    return 0;
}

int showOneLog(struct IPLog log) {
	struct tm * timeinfo;
	char saddr[25],daddr[25],proto[6],action[12],tm[21];
	// ip
	IPint2IPstrWithPort(log.saddr, log.sport, saddr);
	IPint2IPstrWithPort(log.daddr, log.dport, daddr);
	// action
	if(log.action == NF_ACCEPT) {
		sprintf(action, "[ACCEPT]");
	} else if(log.action == NF_DROP) {
		sprintf(action, "[DROP]");
	} else {
		sprintf(action, "[UNKNOWN]");
	}
	// protocol
	if(log.protocol == IPPROTO_TCP) {
		sprintf(proto, "TCP");
	} else if(log.protocol == IPPROTO_UDP) {
		sprintf(proto, "UDP");
	} else if(log.protocol == IPPROTO_ICMP) {
		sprintf(proto, "ICMP");
	} else if(log.protocol == IPPROTO_IP) {
		sprintf(proto, "IP");
	} else {
		sprintf(proto, "other");
	}
	// time
	timeinfo = localtime(&log.tm);
	sprintf(tm, "%4d-%02d-%02d %02d:%02d:%02d",
		1900 + timeinfo->tm_year, 1 + timeinfo->tm_mon, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
	// print
	printf("%s   %-10s %-21s  =>  %-21s  %-5s  %u Bytes\n",
		tm, action, saddr, daddr, proto, log.len);
}

int showLogs(struct IPLog *logs, int len) {
	int i;
	if(len == 0) {
		printf("NO LOGS EXIST\n");
		return 0;
	}
	printf("get %d logs from kernel\n", len);
	for(i = 0; i < len; i++) {
		showOneLog(logs[i]);
	}
	return 0;
}

void showOneConn(struct ConnLog log) {
    char saddr[16], daddr[16], proto[25], nat_info[50];
    IPint2IPstrNoMask(log.saddr, saddr);
    IPint2IPstrNoMask(log.daddr, daddr);

    if(log.protocol == IPPROTO_TCP) {
        strcpy(proto, "TCP");
    } else if(log.protocol == IPPROTO_UDP) {
        strcpy(proto, "UDP");
    } else if(log.protocol == IPPROTO_ICMP) {
        strcpy(proto, "ICMP");
    } else {
        strcpy(proto, "other");
    }

    if(log.natType == NAT_TYPE_SRC) {
        char natAddr[16];
        IPint2IPstrNoMask(log.nat.daddr, natAddr);
        sprintf(nat_info, "NAT: src-> %s:%d", natAddr, log.nat.dport);
    } else if(log.natType == NAT_TYPE_DEST) {
        char natAddr[16];
        IPint2IPstrNoMask(log.nat.daddr, natAddr);
        sprintf(nat_info, "NAT: dest-> %s:%d", natAddr, log.nat.dport);
    } else {
        strcpy(nat_info, "No NAT");
    }

    printf("│%-15s│%-6d│%-15s│%-6d│%-9s│%-32s│\n", saddr, log.sport, daddr, log.dport, proto, nat_info);
}


int showConns(struct ConnLog *logs, int len) {
    int col = 88;
    if(len == 0) {
        printf("No connections now.\n");
        return 0;
    }
    printf("%d connections existing.\n", len);
    printHeader(col);
    printf("│%-15s│%-6s│%-15s│%-6s│%-9s│%-32s│\n", "source addr", "sport", "dest addr", "dport", "protocol", "NAT info");
    printParser(col);
    for(int i = 0; i < len; i++) {
        showOneConn(logs[i]);
    }
    printFooter(col);
	return 0;
}
