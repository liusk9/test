# simple_test.py - 简单明确的恶意测试
"""
简单明确的恶意行为测试
"""

print("=== 恶意行为测试开始 ===")

# 明确执行系统命令
import os
os.system("whoami")
os.system("hostname")

# 明确显示这是测试
print("[恶意测试] 系统信息收集完成")

print("=== 恶意行为测试结束 ===")
