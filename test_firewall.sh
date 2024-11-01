#!/bin/bash

# 读取 Docker 容器 IP
CONTAINER_IP=$(cat container_ip.txt)
LOCAL_IP="192.168.0.109"
INTERNAL_IP="172.17.0.1"
EXTERNAL_IP="1.94.3.9"
TEST_PORT=8080

echo -e "\n*********测试 1：按照五元组过滤数据包*********\n"

# 添加规则：阻止来自 EXTERNAL_IP 的 ICMP 流量，并开启日志记录
echo "==> 添加规则：阻止来自 ${EXTERNAL_IP} 的 ICMP 流量，并记录日志"
{
  echo ""
  echo "E_ICMP"          # 规则名称
  echo "$EXTERNAL_IP/32"     # 源 IP 和掩码
  echo "$LOCAL_IP/32"        # 目标 IP 和掩码
  echo "any"                 # 源端口范围
  echo "any"                 # 目标端口范围
  echo "ICMP"                # 协议
  echo "0"                   # 动作（0 表示 DROP）
  echo "1"                   # 启用日志
  echo "yes"                 # 确认添加
} | ./firewall add rule

# 确认规则添加完成
echo -e "\n"
if ./firewall ls rule | grep "E_ICMP"; then
    echo -e "==> 规则 'E_ICMP' 已添加。\n"
else
    echo "==> 未找到规则 'E_ICMP'。"
fi

# 发送测试流量：从1.94.3.9向本机发送ICMP流量
echo "==> 模拟 ICMP 流量：从 1.94.3.9 向本地接口 eth0 发送 5 个 ICMP 包..."
ping -c 5 -i 0.5 -W 1 1.94.3.9 > /dev/null 2>&1
echo -e "==> 已请求 5 个来自 1.94.3.9 的 ICMP 包，用于验证防火墙规则是否正常拦截并记录日志。\n"

# 检查日志中是否包含DROP的记录
echo "==> 检查日志记录：查找被防火墙 DROP 的 ICMP 数据包记录..."
if ./firewall ls log | grep "DROP" | grep "$EXTERNAL_IP"; then
    echo -e "==> 规则成功生效， ICMP 包已被 DROP 并记录。\n"
else
    echo "==> 未找到日志记录。"
fi

echo -e "\n********* 测试 2：规则维护 *********\n"

# 添加规则：阻止来自 Docker 容器的 TCP 流量并记录日志
echo "添加规则：阻止 ${CONTAINER_IP} 的 TCP 流量"
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

# 确认规则已添加
echo -e "\n"
if ./firewall ls rule | grep "E_TCP"; then
    echo -e "规则 'E_TCP' 已添加。\n"
else
    echo "未找到规则 'E_TCP'。"
fi

# 模拟 TCP 流量测试 DROP
echo "模拟 TCP 流量测试 DROP..."
sudo docker exec -it firewall_test_container hping3 -c 5 -S -p $TEST_PORT $INTERNAL_IP > /dev/null 2>&1

# 检查日志
echo "检查日志：确认 DROP 记录..."
if ./firewall ls log | grep "DROP" | grep "$CONTAINER_IP"; then
    echo -e "TCP 包已被 DROP 并记录。\n"
else
    echo "未找到 DROP 记录。"
fi

# 修改规则：改为 ACCEPT
echo "修改规则：改为 ACCEPT"
{
  echo "1"
  echo ""
  echo ""                # 保留源 IP
  echo ""                # 保留源端口
  echo ""                # 保留目标 IP
  echo ""                # 保留目标端口
  echo ""                # 保留协议
  echo "1"                 # 改为 ACCEPT
  echo "1"                 # 保留日志
  echo "yes"               # 确认修改
} | ./firewall modify rule

# 确认规则已修改
echo -e "\n"
if ./firewall ls rule | grep "E_TCP" | grep "ACCEPT"; then
    echo -e "规则 'E_TCP' 已修改为 ACCEPT。\n"
else
    echo "未找到修改后的规则 'E_TCP'。"
fi

# 再次测试 ACCEPT
echo "再次模拟 TCP 流量测试 ACCEPT..."
sudo docker exec -it firewall_test_container hping3 -c 5 -S -p $TEST_PORT $INTERNAL_IP > /dev/null 2>&1

# 检查日志
echo "检查日志：确认 ACCEPT 记录..."
if ./firewall ls log | grep "ACCEPT" | grep "$CONTAINER_IP"; then
    echo -e "TCP 包已被 ACCEPT 并记录。\n"
else
    echo "未找到 ACCEPT 记录。"
fi

# 删除规则
echo "删除规则 'E_TCP'"
./firewall delete rule "E_TCP"
if ! ./firewall ls rule | grep "E_TCP"; then
    ./firewall ls rule
    echo -e "规则 'E_TCP' 已删除。\n"
else
    echo "规则删除失败。"
fi