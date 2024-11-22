#include "firewall.h"

static struct sock *nlsk = NULL;
extern unsigned int DEFAULT_ACTION;

int nlSend(unsigned int pid, void *data, unsigned int len) {
	int retval;
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	// init sk_buff
	skb = nlmsg_new(len, GFP_ATOMIC);
	if (skb == NULL) {
		printk(KERN_WARNING "[firewall] [netlink] alloc reply nlmsg skb failed!\n");
		return -1;
	}
	nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(len) - NLMSG_HDRLEN, 0);
	// send data
	memcpy(NLMSG_DATA(nlh), data, len);
    //NETLINK_CB(skb).portid = 0;
	NETLINK_CB(skb).dst_group = 0;
	retval = netlink_unicast(nlsk, skb, pid, MSG_DONTWAIT);
	printk(KERN_INFO "[firewall] [netlink] Sent message to user with PID=%d. Message length=%d. Send return value=%d.\n", pid, nlh->nlmsg_len - NLMSG_SPACE(0), retval);
	return retval;
}

void nlRecv(struct sk_buff *skb) {
	void *data;
	struct nlmsghdr *nlh = NULL;
	unsigned int pid,len;
    // check skb
    nlh = nlmsg_hdr(skb);
	if ((nlh->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nlh->nlmsg_len)) {
		printk(KERN_WARNING "[firewall] [netlink] Received illegal netlink packet!\n");
		return;
	}
    // deal data
	data = NLMSG_DATA(nlh);
    pid = nlh->nlmsg_pid;
    len = nlh->nlmsg_len - NLMSG_SPACE(0);
	if(len<sizeof(struct APPRequest)) {
		printk(KERN_WARNING "[firewall] [netlink] packet size < APPRequest!\n");
		return;
	}
	printk(KERN_INFO "[firewall] [netlink] Receive data from user with PID=%d, Message length=%d\n", pid, len);
	dealAppMessage(pid, data, len);
}

struct netlink_kernel_cfg nltest_cfg = {
	.groups = 0,
	.flags = 0,
	.input = nlRecv,
	.cb_mutex = NULL,
	.bind = NULL,
	.unbind = NULL,
	.compare = NULL,
};

struct sock *netlink_init() {
    nlsk = netlink_kernel_create(&init_net, NETLINK_MYFW, &nltest_cfg);
	if (!nlsk) {
		printk(KERN_WARNING "[firewall] [netlink] Can not create a netlink socket.\n");
		return NULL;
	}
	printk("[firewall] [netlink] Succeed to create netlink kernel, nlsk = %p\n", nlsk);
    return nlsk;
}

void netlink_release() {
    netlink_kernel_release(nlsk);
}

int sendMsgToApp(unsigned int pid, const char *msg) {
    void* mem;
    unsigned int rspLen;
    struct nfMessageHeader *rspH;
    rspLen = sizeof(struct nfMessageHeader) + strlen(msg) + 1;
    mem = kzalloc(rspLen, GFP_ATOMIC);
    if(mem == NULL) {
        printk(KERN_WARNING "[firewall] [netlink] sendMsgToApp kzalloc fail.\n");
        return 0;
    }
    rspH = (struct nfMessageHeader *)mem;
    rspH->bodyTp = RSP_MSG;
    rspH->arrayLen = strlen(msg);
    memcpy(mem+sizeof(struct nfMessageHeader), msg, strlen(msg));
    nlSend(pid, mem, rspLen);
    kfree(mem);
    return rspLen;
}

void dealWithSetAction(unsigned int action) {
    if(action != NF_ACCEPT) {
        struct IPRule rule = {
            .smask = 0,
            .dmask = 0,
            .sport = -1,
            .dport = -1
        }; // 清除全部连接
        eraseConnRelated(rule);
    }
}

int dealAppMessage(unsigned int pid, void *msg, unsigned int len) {
    struct APPRequest *req;
    struct nfMessageHeader *rspH;
    void* mem;
    unsigned int rspLen = 0;
    req = (struct APPRequest *) msg;
    switch (req->tp)
    {
    case REQ_GETAllIPLogs:
        mem = formAllIPLogs(req->msg.num, &rspLen);
        if(mem == NULL) {
            printk(KERN_WARNING "[firewall] [logs] Fail to form all logs.\n");
            sendMsgToApp(pid, "Error: Failed to retrieve all IP logs.");
            break;
        }
        nlSend(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_GETAllConns:
        mem = formAllConns(&rspLen);
        if(mem == NULL) {
            printk(KERN_WARNING "[firewall] [connections] Fail to form all connections.\n");
            sendMsgToApp(pid, "Error: Failed to retrieve all connections.");
            break;
        }
        nlSend(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_GETAllIPRules:
        mem = formAllIPRules(&rspLen);
        if(mem == NULL) {
            printk(KERN_WARNING "[firewall] [rules] Failed to retrieve all IP rules.\n");
            sendMsgToApp(pid, "Error: Failed to retrieve all IP rules.");
            break;
        }
        nlSend(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_ADDIPRule:
        if(addIPRuleToChain(req->ruleName, req->msg.ipRule)==NULL) {
            rspLen = sendMsgToApp(pid, "Error: Rule addition failed. No such rule or please retry.");
            printk(KERN_WARNING "[firewall] [rules] Failed to add IP rule '%s'.\n", req->msg.ipRule.name);
        } else {
            rspLen = sendMsgToApp(pid, "Success: Rule added successfully.");
            printk(KERN_INFO "[firewall] [rules] Successfully added IP rule '%s'.\n", req->msg.ipRule.name);
        }
        break;
    case REQ_CHANGEIPRule:
        if(changeIPRuleOfChain(req->num, req->msg.ipRule)==NULL) {
            rspLen = sendMsgToApp(pid, "Error: Rule modification failed. No such rule or please retry.");
            printk(KERN_WARNING "[firewall] [rules] Failed to modify IP rule '%s'.\n", req->msg.ipRule.name);
        } else {
                rspLen = sendMsgToApp(pid, "Success: Rule modified successfully.");
                printk(KERN_INFO "[firewall] [rules] Successfully modified IP rule '%s'.\n", req->msg.ipRule.name);
        }
        break;
    case REQ_DELIPRule:
        rspLen = sizeof(struct nfMessageHeader);
        rspH = (struct nfMessageHeader *)kzalloc(rspLen, GFP_KERNEL);
        if(rspH == NULL) {
            printk(KERN_WARNING "[firewall] [rules] Memory allocation failed for response.\n");
            sendMsgToApp(pid, "Error: Response formation failed, but deletion may have succeeded.");
            break;
        }
        rspH->bodyTp = RSP_Only_Head;
        rspH->arrayLen = delIPRuleFromChain(req->ruleName);
        printk(KERN_INFO "[firewall] [rules] Successfully deleted %d IP rule(s).\n", rspH->arrayLen);
        nlSend(pid, rspH, rspLen);
        kfree(rspH);
        break;

    case REQ_GETNATRules:
        mem = formAllNATRules(&rspLen);
        if(mem == NULL) {
            printk(KERN_WARNING "[firewall] [NAT] Failed to retrieve all NAT rules.\n");
            sendMsgToApp(pid, "Error: Failed to retrieve all NAT rules.");
            break;
        }
        nlSend(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_ADDNATRule:
        if(addNATRuleToChain(req->msg.natRule)==NULL) {
            rspLen = sendMsgToApp(pid, "Error: NAT rule addition failed. Please retry.");
            printk(KERN_WARNING "[firewall] [NAT] Failed to add NAT rule.\n");
        } else {
            rspLen = sendMsgToApp(pid, "Success: NAT rule added successfully.");
            printk(KERN_INFO "[firewall] [NAT] Successfully added NAT rule.\n");
        }
        break;

    case REQ_DELNATRule:
        rspLen = sizeof(struct nfMessageHeader);
        rspH = (struct nfMessageHeader *)kzalloc(rspLen, GFP_KERNEL);
        if (rspH == NULL) {
            printk(KERN_WARNING "[firewall] [NAT] Memory allocation failed for response.\n");
            sendMsgToApp(pid, "Error: Response formation failed, but deletion may have succeeded.");
            break;
        }
        rspH->bodyTp = RSP_Only_Head;
        rspH->arrayLen = delNATRuleFromChain(req->msg.num);
        printk(KERN_INFO "[firewall] [NAT] Successfully deleted %d NAT rule(s).\n", rspH->arrayLen);
        nlSend(pid, rspH, rspLen);
        kfree(rspH);
        break;

    case REQ_SETAction:
        if(req->msg.defaultAction == NF_ACCEPT) {
            DEFAULT_ACTION = NF_ACCEPT;
            rspLen = sendMsgToApp(pid, "Default action set to ACCEPT.");
            printk(KERN_INFO "[firewall] [action] Default action set to ACCEPT.\n");
        } else {
            DEFAULT_ACTION = NF_DROP;
            rspLen = sendMsgToApp(pid, "Default action set to DROP.");
            printk(KERN_INFO "[firewall] [action] Default action set to DROP.\n");
        }
        dealWithSetAction(DEFAULT_ACTION);
        break;

    case REQ_SAVEIPRule:
        if (req->msg.filename == NULL || strlen(req->msg.filename) == 0) {
            rspLen = sendMsgToApp(pid, "Error: Filename for saving rules is not specified.");
            printk(KERN_WARNING "[firewall] [file] No filename provided for saving rules.\n");
        } else {
            int save_result = saveIPRule(req->msg.filename);
            if (save_result != 0) {
                rspLen = sendMsgToApp(pid, "Error: Failed to save IP rules.");
                printk(KERN_WARNING "[firewall] [file] Failed to save IP rules to '%s'.\n", req->msg.filename);
            } else {
                rspLen = sendMsgToApp(pid, "Success: IP rules saved successfully.");
                printk(KERN_INFO "[firewall] [file] IP rules successfully saved to '%s'.\n", req->msg.filename);
            }
        }
        break;

    case REQ_LOADIPRule:
        if (req->msg.filename == NULL || strlen(req->msg.filename) == 0) {
            rspLen = sendMsgToApp(pid, "Error: Filename for loading rules is not specified.");
            printk(KERN_WARNING "[firewall] [file] No filename provided for loading rules.\n");
        } else {
            int load_result = loadIPRule(req->msg.filename);
            if (load_result != 0) {
                rspLen = sendMsgToApp(pid, "Error: Failed to load IP rules.");
                printk(KERN_WARNING "[firewall] [file] Failed to load IP rules from '%s'.\n", req->msg.filename);
            } else {
                rspLen = sendMsgToApp(pid, "Success: IP rules loaded successfully.");
                printk(KERN_INFO "[firewall] [file] IP rules successfully loaded from '%s'.\n", req->msg.filename);
            }
        }
        break;

    case REQ_CLEARIPRule:
        clearAllIPRules();
        rspLen = sendMsgToApp(pid, "Success: Clear all rules successfully.");
        break;

    default:
        rspLen = sendMsgToApp(pid, "Error: Unknown request.");
        printk(KERN_WARNING "[firewall] Unknown request type received.\n");
        break;
    }
    return rspLen;
}