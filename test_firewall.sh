#!/bin/bash

# 读取 Docker 容器 IP
CONTAINER_IP=$(cat container_ip.txt)
LOCAL_IP="192.168.0.109"
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

