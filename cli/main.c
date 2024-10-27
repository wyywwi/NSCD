#include "contact.h"

// 新增过滤规则时的用户交互
struct KernelResponse cmdAddRule() {
    struct KernelResponse empty = { .code = ERROR_CODE_EXIT };
    char after[MAX_RULENAME_LEN+1], name[MAX_RULENAME_LEN+1], saddr[25], daddr[25], sport[15], dport[15], protoS[6];
    unsigned short sportMin, sportMax, dportMin, dportMax;
    unsigned int action = NF_DROP, log = 0, proto, i;

    // 询问插入规则的位置
    printf("Add rule after which rule? (Press Enter to add at the beginning): ");
    fgets(after, sizeof(after), stdin);
    after[strcspn(after, "\n")] = '\0'; // Remove newline character

    // 获取规则名称
    printf("Enter rule name [up to %d characters]: ", MAX_RULENAME_LEN);
    fgets(name, sizeof(name), stdin);
    name[strcspn(name, "\n")] = '\0'; // Remove newline character
    if (strlen(name) == 0) {
        printf("Rule name cannot be empty.\n");
        return empty;
    }

    // 输入源IP和掩码
    while (1) {
        printf("Enter source IP and mask (e.g., 127.0.0.1/32): ");
        if (scanf("%24s", saddr) != 1) {
            printf("Invalid input. Please try again.\n");
            while (getchar() != '\n');
            continue;
        }
        getchar();
        break;
    }

    // 输入目的IP和掩码
    while (1) {
        printf("Enter destination IP and mask (e.g., 127.0.0.1/32): ");
        if (scanf("%24s", daddr) != 1) {
            printf("Invalid input. Please try again.\n");
            while (getchar() != '\n');
            continue;
        }
        getchar();
        break;
    }

    // 输入源端口范围
    while (1) {
        printf("Enter source port range (e.g., 1024-65535 or press Enter for 'any'): ");
        fgets(sport, sizeof(sport), stdin);
        sport[strcspn(sport, "\n")] = '\0';
        if (strlen(sport) == 0 || strcmp(sport, "any") == 0) {
            sportMin = 0;
            sportMax = 0xFFFF;
            break;
        } else if (sscanf(sport, "%hu-%hu", &sportMin, &sportMax) == 2 && sportMin <= sportMax) {
            break;
        } else {
            printf("Invalid port range. Please try again.\n");
        }
    }

    // 输入目的端口范围
    while (1) {
        printf("Enter destination port range (e.g., 1024-65535 or press Enter for 'any'): ");
        fgets(dport, sizeof(dport), stdin);
        dport[strcspn(dport, "\n")] = '\0';
        if (strlen(dport) == 0 || strcmp(dport, "any") == 0) {
            dportMin = 0;
            dportMax = 0xFFFF;
            break;
        } else if (sscanf(dport, "%hu-%hu", &dportMin, &dportMax) == 2 && dportMin <= dportMax) {
            break;
        } else {
            printf("Invalid port range. Please try again.\n");
        }
    }

    // 选择协议
    while (1) {
        printf("Enter protocol (TCP, UDP, ICMP, or press Enter for 'any'): ");
        fgets(protoS, sizeof(protoS), stdin);
        protoS[strcspn(protoS, "\n")] = '\0';
        if (strlen(protoS) == 0 || strcmp(protoS, "any") == 0) {
            proto = IPPROTO_IP;
            break;
        } else if (strcmp(protoS, "TCP") == 0) {
            proto = IPPROTO_TCP;
            break;
        } else if (strcmp(protoS, "UDP") == 0) {
            proto = IPPROTO_UDP;
            break;
        } else if (strcmp(protoS, "ICMP") == 0) {
            proto = IPPROTO_ICMP;
            break;
        } else {
            printf("Unsupported protocol. Please try again.\n");
        }
    }
    // 选择动作
    while (1) {
        printf("Choose action (1 for accept, 0 for drop): ");
        if (scanf("%u", &action) != 1 || (action != NF_ACCEPT && action != NF_DROP)) {
            printf("Invalid action. Please try again.\n");
            while (getchar() != '\n');
        } else {
            break;
        }
    }
    // 选择是否记录日志
    while (1) {
        printf("Enable logging? (1 for yes, 0 for no): ");
        if (scanf("%u", &log) != 1 || (log != 0 && log != 1)) {
            printf("Invalid log option. Please try again.\n");
            while (getchar() != '\n');
        } else {
            break;
        }
    }

    // 确认信息
    printf("\nReview your rule:\n");
    printf("Rule will be added after: %s\n", after[0] ? after : "the first rule");
    printf("Rule name: %s\n", name);
    printf("Source IP/Mask: %s\n", saddr);
    printf("Destination IP/Mask: %s\n", daddr);
    printf("Source port range: %s\n", sport);
    printf("Destination port range: %s\n", dport);
    printf("Protocol: %s\n", protoS);
    printf("Action: %s\n", action == NF_ACCEPT ? "Accept" : "Drop");
    printf("Logging: %s\n\n", log ? "Enabled" : "Disabled");
    printf("Confirm addition (yes/no): ");
    char confirm[4];
    scanf("%3s", confirm);
    if (strcmp(confirm, "yes") != 0) {
        printf("Rule addition cancelled.\n");
        return empty;
    }

    // 添加规则
    return addFilterRule(after, name, saddr, daddr,
                         (((unsigned int)sportMin << 16) | (sportMax & 0xFFFF)),
                         (((unsigned int)dportMin << 16) | (dportMax & 0xFFFF)), proto, log, action);
}


// 修改过滤规则时的用户交互
struct KernelResponse cmdChangeRule() {
    struct KernelResponse empty = { .code = ERROR_CODE_EXIT };
    char name[MAX_RULENAME_LEN+1], saddr[25], daddr[25], sport[15], dport[15], protoS[6];
    unsigned short sportMin, sportMax, dportMin, dportMax;
    unsigned int action = NF_DROP, log = 0, proto, key = 0;

    // 获取规则序号（以1开始）
    while (1) {
        printf("Enter the order number of the rule to be changed (e.g., 1 for the first rule): ");
        if (scanf("%d", &key) != 1 || key <= 0) {
            printf("Invalid rule order. Please try again.\n");
            while (getchar() != '\n');
        } else {
            getchar();
            break;
        }
    }

    // 规则名称输入，按 Enter 保留原值
    printf("Enter new rule name or press Enter to keep existing value [max length = %d]: ", MAX_RULENAME_LEN);
    fgets(name, sizeof(name), stdin);
    name[strcspn(name, "\n")] = '\0'; // Remove newline character
    if (strlen(name) == 0) {
        strcpy(name, "-1"); // Indicates no change
    }

    // 源IP和掩码输入
    printf("Enter new source IP and mask or press Enter to keep existing value (e.g., 192.168.1.1/24): ");
    fgets(saddr, sizeof(saddr), stdin);
    saddr[strcspn(saddr, "\n")] = '\0';
    if (strlen(saddr) == 0) {
        strcpy(saddr, "-1"); // Indicates no change
    }

    // 源端口范围输入
    printf("Enter new source port range or press Enter to keep existing value (e.g., 1024-65535 or 'any'): ");
    fgets(sport, sizeof(sport), stdin);
    sport[strcspn(sport, "\n")] = '\0';
    if (strlen(sport) == 0 || strcmp(sport, "-1") == 0) {
        sportMin = 0;
        sportMax = 0;
    } else if (strcmp(sport, "any") == 0) {
        sportMin = 0;
        sportMax = 0xFFFF;
    } else if (sscanf(sport, "%hu-%hu", &sportMin, &sportMax) != 2 || sportMin > sportMax) {
        printf("Invalid port range. Please try again.\n");
        return empty;
    }

    // 目的IP和掩码输入
    printf("Enter new destination IP and mask or press Enter to keep existing value (e.g., 192.168.1.1/24): ");
    fgets(daddr, sizeof(daddr), stdin);
    daddr[strcspn(daddr, "\n")] = '\0';
    if (strlen(daddr) == 0) {
        strcpy(daddr, "-1"); // Indicates no change
    }

    // 目的端口范围输入
    printf("Enter new destination port range or press Enter to keep existing value (e.g., 1024-65535 or 'any'): ");
    fgets(dport, sizeof(dport), stdin);
    dport[strcspn(dport, "\n")] = '\0';
    if (strlen(dport) == 0 || strcmp(dport, "-1") == 0) {
        dportMin = 0;
        dportMax = 0;
    } else if (strcmp(dport, "any") == 0) {
        dportMin = 0;
        dportMax = 0xFFFF;
    } else if (sscanf(dport, "%hu-%hu", &dportMin, &dportMax) != 2 || dportMin > dportMax) {
        printf("Invalid port range. Please try again.\n");
        return empty;
    }

    // 协议输入
    printf("Enter new protocol or press Enter to keep existing value (TCP, UDP, ICMP, 'any'): ");
    fgets(protoS, sizeof(protoS), stdin);
    protoS[strcspn(protoS, "\n")] = '\0';
    if (strlen(protoS) == 0) {
        proto = 255;  // No change
    } else if (strcmp(protoS, "TCP") == 0) proto = IPPROTO_TCP;
    else if (strcmp(protoS, "UDP") == 0) proto = IPPROTO_UDP;
    else if (strcmp(protoS, "ICMP") == 0) proto = IPPROTO_ICMP;
    else if (strcmp(protoS, "any") == 0) proto = IPPROTO_IP;
    else {
        printf("Unsupported protocol. Please try again.\n");
        return empty;
    }

    // 动作输入
    printf("Enter new action (1 for accept, 0 for drop) or press Enter to keep existing value: ");
    char actionInput[10];
    fgets(actionInput, sizeof(actionInput), stdin);
    actionInput[strcspn(actionInput, "\n")] = '\0';
    if (strlen(actionInput) == 0) {
        action = 2;  // No change
    } else {
        sscanf(actionInput, "%u", &action);
    }

    // 日志记录选项输入
    printf("Enter log option (1 for yes, 0 for no) or press Enter to keep existing value: ");
    char logInput[10];
    fgets(logInput, sizeof(logInput), stdin);
    logInput[strcspn(logInput, "\n")] = '\0';
    if (strlen(logInput) == 0) {
        log = 2;  // No change
    } else {
        sscanf(logInput, "%u", &log);
    }

    printf("\nPlease confirm the changes (yes/no): ");
    char confirm[4];
    fgets(confirm, sizeof(confirm), stdin);
    confirm[strcspn(confirm, "\n")] = '\0';
    if (strcmp(confirm, "yes") != 0) {
        printf("Rule change cancelled.\n");
        return empty;
    }

    return changeFilterRule(key, name, saddr, daddr,
                            (((unsigned int)sportMin << 16) | (sportMax & 0xFFFFu)),
                            (((unsigned int)dportMin << 16) | (dportMax & 0xFFFFu)), proto, log, action);
}


struct KernelResponse cmdAddNATRule() {
    struct KernelResponse empty = { .code = ERROR_CODE_EXIT };
    char saddr[25], daddr[25], port[15];
    unsigned short portMin, portMax;

    // 源IP输入循环
    while (1) {
        printf("Enter source IP and mask (e.g., 127.0.0.1/32): ");
        if (scanf("%24s", saddr) != 1) {
            printf("Invalid input. Please try again.\n");
            while (getchar() != '\n'); // 清空输入缓冲区
            continue;
        }
        break;
    }

    // NAT IP输入循环
    while (1) {
        printf("Enter NAT IP (Gateway IP): ");
        if (scanf("%24s", daddr) != 1) {
            printf("Invalid input. Please try again.\n");
            while (getchar() != '\n'); // 清空输入缓冲区
            continue;
        }
        break;
    }

	getchar();

	// 端口范围输入循环
	while (1) {
		printf("Enter NAT port range (like 'min-max' or 'any', press Enter for 'any'): ");
		if (fgets(port, sizeof(port), stdin) == NULL) {
			printf("Invalid input. Please try again.\n");
			continue;
		}

		// 移除字符串末尾的换行符
		port[strcspn(port, "\n")] = '\0';

		// 检查是否为空输入或 'any'
		if (strlen(port) == 0 || strcmp(port, "any") == 0) {
			portMin = 0;
			portMax = 0xFFFFu;
			break;
		} else if (sscanf(port, "%hu-%hu", &portMin, &portMax) == 2 && portMin <= portMax) {
			break;
		} else {
			printf("Invalid port range. Ensure the format is 'min-max' and min is less than max.\n");
		}
	}

    // 确认步骤
    printf("\nConfirm NAT Rule Addition:\n");
    printf("Source IP: %s\n", saddr);
    printf("NAT IP: %s\n", daddr);
    printf("Port Range: %s\n\n", (portMin == 0 && portMax == 0xFFFFu) ? "any" : port);
    char confirm[4];
    printf("Confirm (yes/no): ");
    scanf("%3s", confirm);
    if (strcmp(confirm, "yes") != 0) {
        printf("NAT rule addition cancelled.\n");
        return empty;
    }

    return addNATRule(saddr, daddr, portMin, portMax);
}


void wrongCommand() {
    printf("Invalid command.\n");
    printf("Usage: firewall <command> <sub-command> [options]\n");
    printf("Commands:\n");
    printf("  add    <rule | nat>                 Add a rule or NAT entry\n");
    printf("  delete <rule | nat>                 Delete a rule by name or NAT entry by number\n");
    printf("  modify <rule>                       Modify an existing rule\n");
    printf("  ls     <rule | nat | log | connect> List rules, NAT entries, logs, or connections\n");
    printf("  save   <rule> <filename>            Save rules to a file\n");
    printf("  load   <rule> <filename>            Load rules from a file\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        wrongCommand();
        return 0;
    }

    struct KernelResponse rsp;
    rsp.code = ERROR_CODE_EXIT;
    const char *command = argv[1];
    const char *sub_command = argv[2];

    if (strcmp(command, "add") == 0) {
        if (strcmp(sub_command, "rule") == 0) {
            rsp = cmdAddRule();
        } else if (strcmp(sub_command, "nat") == 0) {
            rsp = cmdAddNATRule();
        } else {
            wrongCommand();
        }
    } else if (strcmp(command, "delete") == 0) {
        if (strcmp(sub_command, "rule") == 0) {
            if (argc < 4) {
                printf("Please specify the rule name.\n");
            } else if (strlen(argv[3]) > MAX_RULENAME_LEN) {
                printf("Rule name too long!\n");
            } else {
                rsp = delFilterRule(argv[3]);
            }
        } else if (strcmp(sub_command, "nat") == 0) {
            if (argc < 4) {
                printf("Please specify the NAT rule number.\n");
            } else {
                int num;
                sscanf(argv[3], "%d", &num);
                rsp = delNATRule(num);
            }
        } else {
            wrongCommand();
        }
    } else if (strcmp(command, "modify") == 0) {
        if (strcmp(sub_command, "rule") == 0) {
            rsp = cmdChangeRule();
        } else {
            wrongCommand();
        }
    } else if (strcmp(command, "ls") == 0) {
        if (strcmp(sub_command, "rule") == 0) {
            rsp = getAllFilterRules();
        } else if (strcmp(sub_command, "nat") == 0) {
            rsp = getAllNATRules();
        } else if (strcmp(sub_command, "log") == 0) {
            unsigned int num = 0;
            if (argc > 3) {
                sscanf(argv[3], "%u", &num);
            }
            rsp = getLogs(num);
        } else if (strcmp(sub_command, "connect") == 0) {
            rsp = getAllConns();
        } else {
            wrongCommand();
        }
    } else if (strcmp(command, "save") == 0 || strcmp(command, "load") == 0) {
        if (argc < 4) {
            printf("Please specify a filename.\n");
        } else {
            const char *filename = argv[3];
            if (strcmp(command, "save") == 0 && strcmp(sub_command, "rule") == 0) {
                rsp = saveRulesCommand(filename);
            } else if (strcmp(command, "load") == 0 && strcmp(sub_command, "rule") == 0) {
                rsp = loadRulesCommand(filename);
            } else {
                wrongCommand();
            }
        }
    } else {
        wrongCommand();
    }

    dealResponseAtCmd(rsp);
    return 0;
}