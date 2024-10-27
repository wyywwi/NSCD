#include "firewall.h"

void getPort(struct sk_buff *skb, struct iphdr *hdr, unsigned short *src_port, unsigned short *dst_port){
	struct tcphdr *tcpHeader;
	struct udphdr *udpHeader;
	switch(hdr->protocol){
		case IPPROTO_TCP:
			//printk("TCP protocol\n");
			tcpHeader = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
			*src_port = ntohs(tcpHeader->source);
			*dst_port = ntohs(tcpHeader->dest);
			break;
		case IPPROTO_UDP:
			//printk("UDP protocol\n");
			udpHeader = (struct udphdr *)(skb->data + (hdr->ihl * 4));
			*src_port = ntohs(udpHeader->source);
			*dst_port = ntohs(udpHeader->dest);
			break;
		case IPPROTO_ICMP:
		default:
			//printk("other protocol\n");
			*src_port = 0;
			*dst_port = 0;
			break;
	}
}

bool isIPMatch(unsigned int ipl, unsigned int ipr, unsigned int mask) {
	return (ipl & mask) == (ipr & mask);
}

int parseRuleFromString(const char *data, struct IPRule *rule) {
    char *ptr, *token;
    char key[32], value[32];
    char *working_data = kstrdup(data, GFP_KERNEL); // Duplicate string for manipulation
    if (!working_data)
        return -ENOMEM;

    while ((token = strsep(&working_data, ",")) != NULL) {
        ptr = strsep(&token, "=");
        if (!ptr)
            continue;

        strncpy(key, ptr, sizeof(key) - 1);
        key[sizeof(key) - 1] = '\0'; // Ensure null-termination

        ptr = strsep(&token, "=");
        if (!ptr)
            continue;

        strncpy(value, ptr, sizeof(value) - 1);
        value[sizeof(value) - 1] = '\0'; // Ensure null-termination

        // Map key-value pairs to rule structure
        if (strcmp(key, "Name") == 0) {
            strncpy(rule->name, value, MAX_RULENAME_LEN);
        } else if (strcmp(key, "SAddr") == 0) {
            if (kstrtou32(value, 10, &rule->saddr))
                goto error;
        } else if (strcmp(key, "SMask") == 0) {
            if (kstrtou32(value, 10, &rule->smask))
                goto error;
        } else if (strcmp(key, "DAddr") == 0) {
            if (kstrtou32(value, 10, &rule->daddr))
                goto error;
        } else if (strcmp(key, "DMask") == 0) {
            if (kstrtou32(value, 10, &rule->dmask))
                goto error;
        } else if (strcmp(key, "SPort") == 0) {
            if (kstrtou32(value, 10, &rule->sport))
                goto error;
        } else if (strcmp(key, "DPort") == 0) {
            if (kstrtou32(value, 10, &rule->dport))
                goto error;
        } else if (strcmp(key, "Protocol") == 0) {
            if (kstrtou8(value, 10, &rule->protocol))
                goto error;
        } else if (strcmp(key, "Action") == 0) {
            if (kstrtou32(value, 10, &rule->action))
                goto error;
        } else if (strcmp(key, "Log") == 0) {
            if (kstrtou32(value, 10, &rule->log))
                goto error;
        }
    }
    kfree(working_data);
    return 0; // Success

error:
    kfree(working_data);
    return -EINVAL;
}