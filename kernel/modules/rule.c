#include "firewall.h"

static struct IPRule *ipRuleHead = NULL;
static DEFINE_RWLOCK(ipRuleLock);

// 在名称为after的规则后新增一条规则，after为空时则在首部新增一条规则
struct IPRule * addIPRuleToChain(char after[], struct IPRule rule) {
    struct IPRule *newRule,*now;
    newRule = (struct IPRule *) kzalloc(sizeof(struct IPRule), GFP_KERNEL);
    if(newRule == NULL) {
        printk(KERN_WARNING "[firewall] [rules] kzalloc fail.\n");
        return NULL;
    }
    memcpy(newRule, &rule, sizeof(struct IPRule));
    // 新增规则至规则链表
    write_lock(&ipRuleLock);
    if(rule.action != NF_ACCEPT) 
        eraseConnRelated(rule); // 消除新增规则的影响
    if(ipRuleHead == NULL) {
        ipRuleHead = newRule;
        ipRuleHead->nx = NULL;
        write_unlock(&ipRuleLock);
        return newRule;
    }
    if(strlen(after)==0) {
        newRule->nx = ipRuleHead;
        ipRuleHead = newRule;
        write_unlock(&ipRuleLock);
        return newRule;
    }
    for(now=ipRuleHead;now!=NULL;now=now->nx) {
        if(strcmp(now->name, after)==0) {
            newRule->nx = now->nx;
            now->nx = newRule;
            write_unlock(&ipRuleLock);
            return newRule;
        }
    }
    // 添加失败
    write_unlock(&ipRuleLock);
    kfree(newRule);
    return NULL;
}

// 修改第key条规则（序号从1开始）
struct IPRule * changeIPRuleOfChain(int nowI, struct IPRule rule) {
    int i = 1; //nowI==1
    struct IPRule *now;
    // 新增规则至规则链表
    write_lock(&ipRuleLock);
    if(rule.action != NF_ACCEPT) 
        eraseConnRelated(rule); // 消除新增规则的影响
    for(now = ipRuleHead;now !=NULL && i < nowI;now=now->nx, i++) ;
    if(now != NULL) {
        if(rule.saddr!=0) {
            now->saddr = rule.saddr;
            now->smask = rule.smask;
        }
        if(rule.daddr!=0) {
            now->daddr = rule.daddr;
            now->dmask = rule.dmask;
        }
        if(rule.sport != 0 || rule.dport != 0){
            now->sport = rule.sport;
            now->dport = rule.dport;
        }
        now->log = (rule.log!=2)? rule.log: now->log;
        now->action = (rule.action!=2)? rule.action: now->action;
        now->protocol = (rule.protocol!=255)? rule.protocol: now->protocol;
        if(strcmp(rule.name, "-1")!=0)
            strncpy(now->name, rule.name, MAX_RULENAME_LEN);
        write_unlock(&ipRuleLock);
        return now;
    }
    // 添加失败
    write_unlock(&ipRuleLock);
    return NULL;
}

// 删除所有名称为name的规则
int delIPRuleFromChain(char name[]) {
    struct IPRule *now,*tmp;
    int count = 0;
    write_lock(&ipRuleLock);
    while(ipRuleHead!=NULL && strcmp(ipRuleHead->name,name)==0) {
        tmp = ipRuleHead;
        ipRuleHead = ipRuleHead->nx;
        eraseConnRelated(*tmp); // 消除删除规则的影响
        kfree(tmp);
        count++;
    }
    for(now=ipRuleHead;now!=NULL && now->nx!=NULL;) {
        if(strcmp(now->nx->name,name)==0) { // 删除下条规则
            tmp = now->nx;
            now->nx = now->nx->nx;
            eraseConnRelated(*tmp); // 消除删除规则的影响
            kfree(tmp);
            count++;
        } else {
            now = now->nx;
        }
    }
    write_unlock(&ipRuleLock);
    return count;
}

// 将所有规则形成Netlink回包
void* formAllIPRules(unsigned int *len) {
    struct nfMessageHeader *head;
    struct IPRule *now;
    void *mem,*p;
    unsigned int count;
    read_lock(&ipRuleLock);
    for(now=ipRuleHead,count=0;now!=NULL;now=now->nx,count++);
    *len = sizeof(struct nfMessageHeader) + sizeof(struct IPRule)*count;
    mem = kzalloc(*len, GFP_ATOMIC);
    if(mem == NULL) {
        printk(KERN_WARNING "[firewall] [rules] kzalloc fail.\n");
        read_unlock(&ipRuleLock);
        return NULL;
    }
    head = (struct nfMessageHeader *)mem;
    head->bodyTp = RSP_IPRules;
    head->arrayLen = count;
    for(now=ipRuleHead,p=(mem + sizeof(struct nfMessageHeader));now!=NULL;now=now->nx,p=p+sizeof(struct IPRule))
        memcpy(p, now, sizeof(struct IPRule));
    read_unlock(&ipRuleLock);
    return mem;
}

bool matchOneRule(struct IPRule *rule,
 unsigned int sip, unsigned int dip, unsigned short sport, unsigned int dport, u_int8_t proto) {
    return (isIPMatch(sip,rule->saddr,rule->smask) &&
			isIPMatch(dip,rule->daddr,rule->dmask) &&
			(sport >= ((unsigned short)(rule->sport >> 16)) && sport <= ((unsigned short)(rule->sport & 0xFFFFu))) &&
			(dport >= ((unsigned short)(rule->dport >> 16)) && dport <= ((unsigned short)(rule->dport & 0xFFFFu))) &&
			(rule->protocol == IPPROTO_IP || rule->protocol == proto));
}

// 进行过滤规则匹配，isMatch存储是否匹配到规则
struct IPRule matchIPRules(struct sk_buff *skb, int *isMatch) {
    struct IPRule *now,ret;
	unsigned short sport,dport;
	struct iphdr *header = ip_hdr(skb);
	*isMatch = 0;
	getPort(skb,header,&sport,&dport);
	read_lock(&ipRuleLock);
	for(now=ipRuleHead;now!=NULL;now=now->nx) {
		if(matchOneRule(now,ntohl(header->saddr),ntohl(header->daddr),sport,dport,header->protocol)) {
				ret = *now;
				*isMatch = 1;
				break;
		}
	}
	read_unlock(&ipRuleLock);
	return ret;
}

int saveIPRule(const char *filename) {
    struct file *file;
    struct IPRule *rule;
    loff_t pos = 0;
    int err = 0;
    char data[256]; // 数据缓冲区，足以存储一条规则

    file = filp_open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(file)) {
        printk(KERN_ERR "[firewall] [rules] Cannot open file %s.\n", filename);
        return PTR_ERR(file);
    }

    read_lock(&ipRuleLock);
    for (rule = ipRuleHead; rule != NULL; rule = rule->nx) {
        int bytes;
        // 格式化规则数据
        bytes = snprintf(data, sizeof(data), "Name=%s,SAddr=%u,SMask=%u,DAddr=%u,DMask=%u,SPort=%u,DPort=%u,Protocol=%u,Action=%u,Log=%u\n",
            rule->name, rule->saddr, rule->smask, rule->daddr, rule->dmask, rule->sport, rule->dport, rule->protocol, rule->action, rule->log);
        // 写入文件
        if (kernel_write(file, data, bytes, &pos) < 0) {
            printk(KERN_ERR "[firewall] [rules] Failed to write to file %s.\n", filename);
            err = -EIO;
            break;
        }
    }
    read_unlock(&ipRuleLock);

    filp_close(file, NULL);
    return err;
}

int loadIPRule(const char *filename) {
    struct file *file;
    loff_t pos = 0;
    char buf[256];
    ssize_t bytes_read;
    int err = 0;

    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "[firewall] [rules] Cannot open file %s.\n", filename);
        return PTR_ERR(file);
    }

    while ((bytes_read = kernel_read(file, buf, sizeof(buf) - 1, &pos)) > 0) {
        buf[bytes_read] = '\0';
        struct IPRule rule;
        if (parseRuleFromString(buf, &rule) == 0) {
            if (addIPRuleToChain("", rule) == NULL) {
                printk(KERN_ERR "[firewall] [rules] Failed to add rule from %s.\n", filename);
                err = -EINVAL;
                break;
            }
        } else {
            printk(KERN_ERR "[firewall] [rules] Failed to parse rule from %s.\n", filename);
            err = -EINVAL;
        }
    }

    if (bytes_read < 0) {
        printk(KERN_ERR "[firewall] [rules] Error reading from file %s.\n", filename);
        err = bytes_read;
    }

    filp_close(file, NULL);
    return err;
}

// 删除所有规则
void clearAllIPRules(void) {
    struct IPRule *curr, *tmp;

    write_lock(&ipRuleLock);

    curr = ipRuleHead;
    while (curr != NULL) {
        tmp = curr;
        ipRuleHead = curr->nx; // 将头指针指向下一个规则
        eraseConnRelated(*tmp); // 清除规则对连接的影响
        kfree(tmp); // 释放当前规则的内存
        curr = ipRuleHead; // 更新当前指针为下一个规则
    }

    ipRuleHead = NULL; // 确保链表头为 NULL，表示已清空所有规则

    write_unlock(&ipRuleLock);
    printk(KERN_INFO "[firewall] [rules] All rules have been cleared.\n");
}