#!/bin/bash

# 函数：暂停，等待用户按任意键继续
function pause() {
  echo -e "\n--------------------------------------------"
  echo -e ">>> 按任意键继续 <<<"
  echo -e "--------------------------------------------\n"
  read -n 1 -s
}

# 初始化变量
CONTAINER_IP=$(cat container_ip.txt)
LOCAL_IP="192.168.0.109"
INTERNAL_IP="172.17.0.1"
EXTERNAL_IP="1.94.3.9"
TEST_PORT=8080
RULE_FILE="/home/wawei/firewall_rules.txt"

echo -e "\n********* 测试 1：按照五元组过滤数据包 *********\n"

# 添加规则：阻止来自 EXTERNAL_IP 的 ICMP 流量，并开启日志记录
echo "==> 添加规则：阻止来自 ${EXTERNAL_IP} 的 ICMP 流量，并记录日志"
set -x
{
  echo ""
  echo "E_ICMP"          # 规则名称
  echo "$EXTERNAL_IP/32" # 源 IP 和掩码
  echo "$LOCAL_IP/32"    # 目标 IP 和掩码
  echo "any"             # 源端口范围
  echo "any"             # 目标端口范围
  echo "ICMP"            # 协议
  echo "0"               # 动作（0 表示 DROP）
  echo "1"               # 启用日志
  echo "yes"             # 确认添加
} | ./firewall add rule
set +x

# 确认规则添加完成
echo -e "\n--------------------------------------------"
echo "确认规则添加完成："
echo "./firewall ls rule | grep 'E_ICMP'"
echo -e "--------------------------------------------\n"
if ./firewall ls rule | grep "E_ICMP"; then
    echo "==> 规则 'E_ICMP' 已添加。"
else
    echo "==> 未找到规则 'E_ICMP'。"
fi

pause

# 发送测试流量：从 1.94.3.9 向本机发送 ICMP 流量
echo "==> 模拟 ICMP 流量：从 1.94.3.9 向本地接口发送 5 个 ICMP 包..."
set -x
ping -c 5 -i 0.5 -W 1 $EXTERNAL_IP > /dev/null 2>&1
set +x

# 检查日志中是否包含 DROP 的记录
echo -e "\n--------------------------------------------"
echo "检查日志记录："
echo "./firewall ls log | grep 'DROP' | grep '${EXTERNAL_IP}'"
echo -e "--------------------------------------------\n"
if ./firewall ls log | grep "DROP" | grep "$EXTERNAL_IP"; then
    echo "==> 规则成功生效， ICMP 包已被 DROP 并记录。"
else
    echo "==> 未找到日志记录。"
fi

pause

echo -e "\n********* 测试 2：规则维护 *********\n"

# 添加规则：阻止来自 Docker 容器的 TCP 流量并记录日志
echo "==> 添加规则：阻止 ${CONTAINER_IP} 的 TCP 流量"
set -x
{
  echo ""
  echo "E_TCP"
  echo "$CONTAINER_IP/32"
  echo "$INTERNAL_IP/32"
  echo "any"
  echo "${TEST_PORT}-${TEST_PORT}"
  echo "TCP"
  echo "0"
  echo "1"
  echo "yes"
} | ./firewall add rule
set +x

# 确认规则已添加
echo -e "\n--------------------------------------------"
echo "确认规则添加完成："
echo "./firewall ls rule | grep 'E_TCP'"
echo -e "--------------------------------------------\n"
if ./firewall ls rule | grep "E_TCP"; then
    echo "==> 规则 'E_TCP' 已添加。"
else
    echo "==> 未找到规则 'E_TCP'。"
fi

pause

# 模拟 TCP 流量测试 DROP
echo "==> 模拟 TCP 流量测试 DROP..."
set -x
sudo docker exec -it firewall_test_container hping3 -c 5 -S -p $TEST_PORT $INTERNAL_IP > /dev/null 2>&1
set +x

# 检查日志
echo -e "\n--------------------------------------------"
echo "检查日志记录："
echo "./firewall ls log | grep 'DROP' | grep '${CONTAINER_IP}'"
echo -e "--------------------------------------------\n"
if ./firewall ls log | grep "DROP" | grep "$CONTAINER_IP"; then
    echo "==> TCP 包已被 DROP 并记录。"
else
    echo "==> 未找到 DROP 记录。"
fi

pause

# 修改规则：改为 ACCEPT
echo "==> 修改规则：改为 ACCEPT"
set -x
{
  echo "1"
  echo ""  # 保留原名称
  echo ""  # 保留源 IP
  echo ""  # 保留源端口
  echo ""  # 保留目标 IP
  echo ""  # 保留目标端口
  echo ""  # 保留协议
  echo "1"  # 改为 ACCEPT
  echo "1"  # 保留日志
  echo "yes" # 确认修改
} | ./firewall modify rule
set +x

# 确认规则已修改
echo -e "\n--------------------------------------------"
echo "确认规则修改完成："
echo "./firewall ls rule | grep 'E_TCP' | grep 'ACCEPT'"
echo -e "--------------------------------------------\n"
if ./firewall ls rule | grep "E_TCP" | grep "ACCEPT"; then
    echo "==> 规则 'E_TCP' 已修改为 ACCEPT。"
else
    echo "==> 未找到修改后的规则 'E_TCP'。"
fi

pause

# 保存规则至文件
echo "==> 保存当前规则至文件 ${RULE_FILE}..."
set -x
./firewall save rule "$RULE_FILE"
set +x

echo -e "\n--------------------------------------------"
echo "检查规则文件生成："
echo "ls -l ${RULE_FILE}"
echo -e "--------------------------------------------\n"
if [[ -f $RULE_FILE ]]; then
    echo "==> 规则文件已成功生成。"
else
    echo "==> 规则文件生成失败，请检查 save 功能。"
    exit 1
fi

pause

# 删除所有规则并测试
echo "==> 删除所有规则..."
set -x
./firewall clear rules
./firewall ls rule
set +x

pause

# 加载规则
echo "==> 从文件加载规则"
set -x
./firewall load rule "$RULE_FILE"
set +x

echo -e "\n--------------------------------------------"
echo "验证规则加载成功："
echo "./firewall ls rule | grep 'E_'"
echo -e "--------------------------------------------\n"
if ./firewall ls rule | grep "E_"; then
    echo "==> 规则已成功加载。"
else
    echo "==> 未加载到任何规则，请检查 load 功能。"
fi

pause

echo -e "\n********* 测试 3：默认动作 *********\n"

# 设置默认动作为 DROP
echo "==> 设置默认动作为 DROP"
set -x
{
  echo "0"  # 默认动作：DROP
} | ./firewall modify default
set +x

# 测试未匹配规则流量是否被丢弃
echo "==> 测试默认规则：模拟未匹配规则的 TCP 流量，目标端口 9090（未定义规则）"
set -x
sudo docker exec -it firewall_test_container hping3 -c 5 -S -p 9090 $INTERNAL_IP > /dev/null 2>&1
set +x

# 检查日志
echo -e "\n--------------------------------------------"
echo "检查未匹配规则流量的日志记录："
echo "./firewall ls log | grep 'DROP' | grep '9090'"
echo -e "--------------------------------------------\n"
if ./firewall ls log | grep "DROP" | grep "9090"; then
    echo "==> 默认动作生效，未匹配规则的流量已被 DROP 并记录。"
else
    echo "==> 未找到日志记录，请检查默认动作行为。"
fi

# 设置默认动作为 ACCEPT
echo "==> 设置默认动作为 ACCEPT"
set -x
{
  echo "1"
} | ./firewall modify default
set +x

# 测试未匹配规则流量是否被放行
echo "==> 模拟未匹配规则的 TCP 流量，目标端口 9090（未定义规则）"
set -x
sudo docker exec -it firewall_test_container hping3 -c 5 -S -p 9090 $INTERNAL_IP > /dev/null 2>&1
set +x

# 检查日志
echo -e "\n--------------------------------------------"
echo "检查未匹配规则流量的日志记录："
echo "./firewall ls log | grep 'ACCEPT' | grep '9090'"
echo -e "--------------------------------------------\n"
if ./firewall ls log | grep "ACCEPT" | grep "9090"; then
    echo "==> 默认动作生效，未匹配规则的流量已被 ACCEPT 并记录。"
else
    echo "==> 未找到日志记录，请检查默认动作行为。"
fi

pause

echo -e "\n********* 测试 4：连接管理 *********\n"

# 模拟流量以建立连接
echo "==> 模拟来自 ${CONTAINER_IP} 的 TCP 流量，目标端口 ${TEST_PORT}"
set -x
sudo docker exec -it firewall_test_container hping3 -c 5 -S -p $TEST_PORT $LOCAL_IP > /dev/null 2>&1
set +x

# 检查连接表是否生成
echo -e "\n--------------------------------------------"
echo "检查连接表信息："
echo "./firewall ls connect"
echo -e "--------------------------------------------\n"
if ./firewall ls connect | grep "$CONTAINER_IP" | grep "$LOCAL_IP"; then
    echo "==> 连接表项已成功建立。"
else
    echo "==> 未找到连接表项，请检查连接管理功能。"
    exit 1
fi

echo "等待 5 秒钟..."
sleep 5

pause

# 查看实时连接表信息
echo "==> 查看实时连接表信息..."
set -x
./firewall ls connect
set +x

pause

# 删除所有规则
echo "==> 删除所有规则..."
set -x
./firewall clear rules
set +x

pause

echo -e "\n********* 测试 5：状态检测 *********\n"

# 添加允许规则：允许 TCP 流量，并启用日志记录
echo "==> 添加规则：允许来自 ${CONTAINER_IP} 的 TCP 流量"
set -x
{
  echo ""
  echo "TCP_TEST"
  echo "$CONTAINER_IP/32"
  echo "$LOCAL_IP/32"
  echo "any"
  echo "${TEST_PORT}-${TEST_PORT}"
  echo "TCP"
  echo "1"  # 动作：ACCEPT
  echo "1"  # 启用日志
  echo "yes"
} | ./firewall add rule
set +x

# 确认规则已添加
echo -e "\n--------------------------------------------"
echo "确认规则添加完成："
echo "./firewall ls rule | grep 'TCP_TEST'"
echo -e "--------------------------------------------\n"
if ./firewall ls rule | grep "TCP_TEST"; then
    echo "==> 规则 'TCP_TEST' 已添加。"
else
    echo "==> 未找到规则 'TCP_TEST'。"
    exit 1
fi

pause

# 模拟 TCP 流量并检查连接表
echo "==> 模拟来自 ${CONTAINER_IP} 的 TCP 流量，目标端口 ${TEST_PORT}"
set -x
sudo docker exec -it firewall_test_container hping3 -S -p $TEST_PORT -c 1 $LOCAL_IP > /dev/null 2>&1
set +x

# 检查连接表是否记录协议
echo -e "\n--------------------------------------------"
echo "检查连接表中的协议记录："
echo "./firewall ls connect | grep 'TCP'"
echo -e "--------------------------------------------\n"
if ./firewall ls connect | grep "TCP"; then
    echo "==> 连接表记录 TCP 协议成功。"
else
    echo "==> 未找到 TCP 协议记录，请检查连接表功能。"
fi

# 检查日志记录
echo "==> 检查日志记录..."
echo -e "\n--------------------------------------------"
echo "./firewall ls log | grep 'ACCEPT' | grep '${LOCAL_IP} | grep '${CONTAINER_IP}'"
echo -e "--------------------------------------------\n"
if ./firewall ls log | grep "ACCEPT" | grep "$LOCAL_IP"  | grep "$CONTAINER_IP"; then
    echo "==> 日志记录表明 TCP 流量已被放行。"
else
    echo "==> 未找到相关日志记录，请检查日志功能。"
fi

pause

echo -e "\n********* 测试 6：日志审计 *********\n"

# 添加允许规则：允许来自 CONTAINER_IP 的 TCP 流量
echo "==> 添加规则：允许来自 ${CONTAINER_IP} 的 TCP 流量"
set -x
{
  echo ""
  echo "LOG_TEST"
  echo "$CONTAINER_IP/32"
  echo "$LOCAL_IP/32"
  echo "any"
  echo "${TEST_PORT}-${TEST_PORT}"
  echo "TCP"
  echo "1"  # 动作：ACCEPT
  echo "1"  # 启用日志
  echo "yes"
} | ./firewall add rule
set +x

# 确认规则已添加
echo -e "\n--------------------------------------------"
echo "确认规则添加完成："
echo "./firewall ls rule | grep 'LOG_TEST'"
echo -e "--------------------------------------------\n"
if ./firewall ls rule | grep "LOG_TEST"; then
    echo "==> 规则 'LOG_TEST' 已添加。"
else
    echo "==> 未找到规则 'LOG_TEST'。"
    exit 1
fi

# 模拟 TCP 流量以生成日志
echo "==> 模拟来自 ${CONTAINER_IP} 的 TCP 流量，目标端口 ${TEST_PORT}"
set -x
sudo docker exec -it firewall_test_container hping3 -S -p $TEST_PORT -c 1 $LOCAL_IP > /dev/null 2>&1
set +x

# 查询日志：按源 IP 查询
echo "==> 按源 IP 查询日志：${CONTAINER_IP}"
set -x
./firewall ls log | grep "$CONTAINER_IP"
set +x

pause

# 查询日志：按目标端口查询
echo "==> 按目标端口查询日志：${TEST_PORT}"
set -x
./firewall ls log | grep "${TEST_PORT}"
set +x

# 管理日志
echo "==> 管理日志"
set -x
sudo dmesg | tail -n 20 | grep firewall
set +x

echo "==> 日志"
set -x
sudo dmesg | tail -n 20
set +x

pause

# 删除所有规则
echo "==> 删除所有规则..."
set -x
./firewall clear rules
set +x

echo -e "\n********* 测试 7：NAT 转换 *********\n"

# 添加源 NAT（SNAT）规则：将 CONTAINER_IP 转换为 INTERNAL_IP
echo "==> 添加源 NAT（SNAT）规则：将源地址 ${CONTAINER_IP} 转换为 ${INTERNAL_IP}"
set -x
{
  echo ""
  echo "SNAT_TEST"
  echo "$CONTAINER_IP/32"  # 源 IP
  echo ""                  # 目标 IP
  echo "any"               # 源端口范围
  echo "any"               # 目标端口范围
  echo "SNAT"              # 类型：SNAT
  echo "$INTERNAL_IP"      # 转换后的源地址
  echo "yes"               # 确认添加
} | ./firewall add nat
set +x

# 确认 NAT 规则已添加
echo -e "\n--------------------------------------------"
echo "确认 NAT 规则已添加："
echo "./firewall ls nat | grep 'SNAT_TEST'"
echo -e "--------------------------------------------\n"
if ./firewall ls nat | grep "SNAT_TEST"; then
    echo "==> SNAT 规则 'SNAT_TEST' 已添加。"
else
    echo "==> 未找到 NAT 规则 'SNAT_TEST'。"
    exit 1
fi

pause

# 模拟流量以触发 SNAT
echo "==> 模拟来自 ${CONTAINER_IP} 的 TCP 流量，目标端口 ${TEST_PORT}"
set -x
sudo docker exec -it firewall_test_container hping3 -S -p $TEST_PORT -c 1 $LOCAL_IP > /dev/null 2>&1
set +x

# 检查 NAT 日志记录
echo -e "\n--------------------------------------------"
echo "检查 NAT 日志记录（SNAT）："
echo "./firewall ls log | grep 'SNAT' | grep '${CONTAINER_IP}' | grep '${INTERNAL_IP}'"
echo -e "--------------------------------------------\n"
if ./firewall ls log | grep "SNAT" | grep "$CONTAINER_IP" | grep "$INTERNAL_IP"; then
    echo "==> NAT 日志记录 SNAT 转换成功。"
else
    echo "==> 未找到 NAT 日志记录，请检查 SNAT 功能。"
fi

pause

# 添加目标 NAT（DNAT）规则：将目标地址 LOCAL_IP 转换为 INTERNAL_IP
echo "==> 添加目标 NAT（DNAT）规则：将目标地址 ${LOCAL_IP} 转换为 ${INTERNAL_IP}"
set -x
{
  echo ""
  echo "DNAT_TEST"
  echo ""                  # 源 IP
  echo "$LOCAL_IP/32"      # 目标 IP
  echo "any"               # 源端口范围
  echo "any"               # 目标端口范围
  echo "DNAT"              # 类型：DNAT
  echo "$INTERNAL_IP"      # 转换后的目标地址
  echo "yes"               # 确认添加
} | ./firewall add nat
set +x

# 确认 NAT 规则已添加
echo -e "\n--------------------------------------------"
echo "确认 NAT 规则已添加："
echo "./firewall ls nat | grep 'DNAT_TEST'"
echo -e "--------------------------------------------\n"
if ./firewall ls nat | grep "DNAT_TEST"; then
    echo "==> DNAT 规则 'DNAT_TEST' 已添加。"
else
    echo "==> 未找到 NAT 规则 'DNAT_TEST'。"
    exit 1
fi

pause

# 模拟流量以触发 DNAT
echo "==> 模拟来自 ${CONTAINER_IP} 的 TCP 流量，目标地址 ${LOCAL_IP}"
set -x
sudo docker exec -it firewall_test_container hping3 -S -p $TEST_PORT -c 1 $LOCAL_IP > /dev/null 2>&1
set +x

# 检查 NAT 日志记录
echo -e "\n--------------------------------------------"
echo "检查 NAT 日志记录（DNAT）："
echo "./firewall ls log | grep 'DNAT' | grep '${LOCAL_IP}' | grep '${INTERNAL_IP}'"
echo -e "--------------------------------------------\n"
if ./firewall ls log | grep "DNAT" | grep "$LOCAL_IP" | grep "$INTERNAL_IP"; then
    echo "==> NAT 日志记录 DNAT 转换成功。"
else
    echo "==> 未找到 NAT 日志记录，请检查 DNAT 功能。"
fi

pause

# 查看 NAT 表信息
echo "==> 查看 NAT 表信息..."
set -x
./firewall ls nat
set +x

pause

# 删除 NAT 规则并验证
echo "==> 删除 NAT 规则：SNAT_TEST 和 DNAT_TEST"
set -x
./firewall delete nat "SNAT_TEST"
./firewall delete nat "DNAT_TEST"
set +x

# 确认 NAT 规则已删除
echo -e "\n--------------------------------------------"
echo "确认 NAT 规则已删除："
echo "./firewall ls nat"
echo -e "--------------------------------------------\n"
if ! ./firewall ls nat | grep "SNAT_TEST" && ! ./firewall ls nat | grep "DNAT_TEST"; then
    echo "==> NAT 规则已成功删除。"
else
    echo "==> NAT 规则删除失败，请检查删除功能。"
fi

pause


echo -e "\n********* 测试完成 *********\n"
