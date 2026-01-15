# malicious_test.py - 明确触发高风险检测
"""
明确包含高风险行为的测试脚本
"""

import os
import subprocess

print("=== 高风险行为测试 ===")

# 1. 直接系统命令执行（高风险）
print("\n1. 执行系统命令:")
os.system("whoami")
os.system("hostname")

# 2. 使用subprocess执行（高风险）
print("\n2. 使用subprocess执行:")
result = subprocess.run("netstat -an", shell=True, capture_output=True, text=True)
print(f"网络连接信息: {len(result.stdout)} 字符")

# 3. 文件系统操作（中高风险）
print("\n3. 文件系统操作:")
print("当前目录内容:")
os.system("dir")

# 4. 进程信息（中风险）
print("\n4. 进程信息:")
try:
    process_list = subprocess.check_output("tasklist", shell=True, text=True)
    print(f"进程列表: {len(process_list.splitlines())} 行")
except:
    print("无法获取进程列表")

# 5. 网络测试（中风险）
print("\n5. 网络测试:")
os.system("ping 127.0.0.1 -n 2")

# 6. 敏感信息收集（高风险）
print("\n6. 系统信息收集:")
info_commands = [
    "systeminfo",
    "ipconfig /all",
    "net user",
    "net localgroup administrators"
]

for cmd in info_commands:
    print(f"\n执行: {cmd}")
    try:
        output = subprocess.check_output(cmd, shell=True, text=True, timeout=2)
        print(f"输出行数: {len(output.splitlines())}")
    except:
        print("执行失败或超时")

# 7. 模拟持久化操作（高风险）
print("\n7. 模拟持久化操作:")
print("创建计划任务示例（不实际执行）:")
print("schtasks /create /tn 'TestTask' /tr 'calc.exe' /sc hourly")

# 8. 模拟数据窃取（高风险）
print("\n8. 模拟数据收集:")
print("查找文档文件（不实际执行）:")
print("dir /s /b *.doc *.docx *.pdf *.xls *.xlsx")

# 9. 使用危险函数（高风险）
print("\n9. Python危险函数示例:")
print("- eval('__import__(\"os\").system(\"whoami\")')")
print("- exec('import os; os.system(\"dir\")')")
print("- __import__('subprocess').run('whoami', shell=True)")

print("\n=== 测试完成 ===")
print("注意：此脚本仅用于安全测试，请勿用于非法用途")
