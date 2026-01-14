#!/usr/bin/env python3
"""
测试用漏洞程序 - 包含多种常见安全漏洞
用于测试开源软件后门木马与漏洞检测系统
"""

import os
import sys
import subprocess
import re

# 1. 代码注入漏洞
def code_injection():
    """演示代码注入漏洞"""
    user_input = input("请输入一个表达式: ")
    result = eval(user_input)  # 漏洞：直接执行用户输入
    print(f"结果: {result}")

# 2. 命令注入漏洞
def command_injection():
    """演示命令注入漏洞"""
    filename = input("请输入文件名: ")
    # 漏洞：未过滤的用户输入直接传递给系统命令
    os.system(f"cat {filename}")
    
    # 另一种命令注入方式
    subprocess.call(f"ls -la {filename}", shell=True)  # 漏洞：shell=True 允许命令注入

# 3. 路径遍历漏洞
def path_traversal():
    """演示路径遍历漏洞"""
    filename = input("请输入要读取的文件: ")
    # 漏洞：未验证路径，允许访问任意文件
    with open(f"files/{filename}", "r") as f:
        content = f.read()
    print(f"文件内容: {content}")

# 4. 硬编码凭证
def hardcoded_credentials():
    """演示硬编码凭证漏洞"""
    # 漏洞：硬编码的数据库凭证
    db_config = {
        "host": "localhost",
        "user": "admin",
        "password": "password123",  # 漏洞：硬编码密码
        "database": "test_db"
    }
    print(f"连接到数据库: {db_config['host']}")

# 5. 不安全的文件操作
def insecure_file_operation():
    """演示不安全的文件操作"""
    filename = input("请输入要写入的文件名: ")
    content = input("请输入要写入的内容: ")
    # 漏洞：直接写入文件，未验证文件名和内容
    with open(filename, "w") as f:
        f.write(content)
    print(f"内容已写入 {filename}")

# 6. 未验证的输入
def unvalidated_input():
    """演示未验证的输入漏洞"""
    age = input("请输入您的年龄: ")
    # 漏洞：未验证输入是否为数字
    print(f"您的年龄是 {age} 岁")
    next_year = int(age) + 1  # 可能导致 ValueError
    print(f"明年您将 {next_year} 岁")

# 7. 不安全的正则表达式
def insecure_regex():
    """演示不安全的正则表达式漏洞"""
    user_input = input("请输入一个字符串
