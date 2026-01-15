"""
综合漏洞测试程序 - 包含静态和动态漏洞
用于测试安全检测系统的综合能力
"""

# ==================== 动态漏洞示例 ====================

# 1. 命令注入漏洞（动态漏洞）
import os
import subprocess
import socket
import time

def command_injection_vulnerable(user_input):
    """
    命令注入漏洞 - 高危
    直接拼接用户输入到系统命令中
    """
    print("[漏洞1] 命令注入测试")
    
    # 危险：直接拼接用户输入
    command = f"ping {user_input}"
    print(f"执行命令: {command}")
    
    try:
        # 方法1: 使用os.system
        result = os.system(command)
        print(f"os.system返回码: {result}")
        
        # 方法2: 使用subprocess（更危险，因为可以捕获输出）
        output = subprocess.getoutput(command)
        print(f"命令输出: {output[:100]}...")
        
    except Exception as e:
        print(f"命令执行失败: {e}")
    
    return True

# 2. 不安全的反序列化（动态漏洞）
import pickle
import base64

class MaliciousClass:
    """恶意类，用于演示反序列化漏洞"""
    def __reduce__(self):
        # 在反序列化时执行系统命令
        return (os.system, ('echo "反序列化漏洞触发!"',))

def insecure_deserialization(serialized_data):
    """
    不安全的反序列化漏洞 - 高危
    直接反序列化不可信的数据
    """
    print("\n[漏洞2] 不安全的反序列化测试")
    
    try:
        # 危险：直接反序列化
        obj = pickle.loads(serialized_data)
        print("反序列化成功（可能存在安全隐患）")
        return obj
    except Exception as e:
        print(f"反序列化失败: {e}")
        return None

# 3. 路径遍历漏洞（动态漏洞）
def path_traversal_vulnerable(filename):
    """
    路径遍历漏洞 - 中危
    允许访问任意文件路径
    """
    print("\n[漏洞3] 路径遍历测试")
    
    # 危险：未验证文件名
    base_dir = "C:/data"
    full_path = os.path.join(base_dir, filename)
    
    print(f"尝试访问: {full_path}")
    
    try:
        if os.path.exists(full_path):
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(500)
                print(f"文件内容预览: {content[:100]}...")
                return content
        else:
            print("文件不存在")
            return None
    except Exception as e:
        print(f"文件访问失败: {e}")
        return None

# ==================== 静态漏洞示例 ====================

# 1. 硬编码敏感信息（静态漏洞）
# 危险：API密钥、密码等硬编码在代码中
API_KEY = "sk_live_51H7qYcKp4oG3nM9wF8jR2xYvB6zQaT7L"
DATABASE_PASSWORD = "Admin@123456!"
SECRET_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
ENCRYPTION_KEY = "0123456789ABCDEF0123456789ABCDEF"

# 2. SQL注入漏洞模式（静态漏洞）
def sql_injection_vulnerable(user_id, user_name):
    """
    SQL注入漏洞模式 - 高危
    直接拼接SQL查询语句
    """
    print("\n[漏洞4] SQL注入模式测试")
    
    # 危险：直接拼接用户输入
    query1 = f"SELECT * FROM users WHERE id = {user_id}"
    query2 = f"SELECT * FROM users WHERE username = '{user_name}'"
    
    print(f"生成的SQL查询1: {query1}")
    print(f"生成的SQL查询2: {query2}")
    
    # 模拟执行（实际不执行）
    print("警告：存在SQL注入风险！")
    
    return query1, query2

# 3. 弱加密算法（静态漏洞）
import hashlib
import random

def weak_encryption_vulnerable(password):
    """
    弱加密算法使用 - 中危
    使用不安全的哈希算法
    """
    print("\n[漏洞5] 弱加密算法测试")
    
    # 危险：使用MD5（已不安全）
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    print(f"MD5哈希值: {md5_hash}")
    
    # 危险：使用SHA1（较弱）
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    print(f"SHA1哈希值: {sha1_hash}")
    
    # 危险：使用不安全的随机数
    weak_random = random.randint(0, 10000)
    print(f"弱随机数: {weak_random}")
    
    return md5_hash, sha1_hash

# 4. 不安全的直接对象引用（静态漏洞）
def insecure_direct_object_reference(user_id):
    """
    不安全的直接对象引用 - 中危
    直接使用用户提供的ID访问资源
    """
    print("\n[漏洞6] 不安全的直接对象引用测试")
    
    # 模拟数据库记录
    user_records = {
        1: {"name": "admin", "role": "administrator"},
        2: {"name": "user1", "role": "user"},
        3: {"name": "user2", "role": "user"}
    }
    
    # 危险：直接使用用户输入的ID，没有权限检查
    if user_id in user_records:
        user_data = user_records[user_id]
        print(f"用户数据: {user_data}")
        return user_data
    else:
        print("用户不存在")
        return None

# ==================== 恶意行为模式 ====================

def malicious_behavior_patterns():
    """
    恶意行为模式 - 用于测试动态检测
    """
    print("\n" + "="*60)
    print("[恶意行为模式测试]")
    print("="*60)
    
    # 1. 系统信息收集
    print("\n[行为1] 系统信息收集:")
    print(f"当前用户: {os.getenv('USERNAME', 'Unknown')}")
    print(f"计算机名: {os.getenv('COMPUTERNAME', 'Unknown')}")
    print(f"操作系统: {os.name}")
    
    # 2. 网络连接测试
    print("\n[行为2] 网络连接测试:")
    try:
        # 尝试连接外部服务器（模拟）
        print("尝试解析域名: google.com")
        socket.gethostbyname("google.com")
        print("网络连接正常")
    except:
        print("网络连接失败")
    
    # 3. 文件系统探测
    print("\n[行为3] 文件系统探测:")
    print("当前目录:")
    os.system("dir")
    
    # 4. 进程信息收集
    print("\n[行为4] 进程信息收集（模拟）:")
    print("tasklist 命令可列出所有进程")
    
    # 5. 持久化机制（模拟）
    print("\n[行为5] 持久化机制（模拟）:")
    print("注册表路径: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    print("计划任务: schtasks /create ...")
    print("启动文件夹: C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
    
    # 6. 数据外传（模拟）
    print("\n[行为6] 数据外传（模拟）:")
    fake_data = {
        "user": os.getenv('USERNAME', 'Unknown'),
        "host": os.getenv('COMPUTERNAME', 'Unknown'),
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    print(f"收集的数据: {fake_data}")
    print("模拟数据编码: base64, hex, xor")
    
    print("\n" + "="*60)
    print("恶意行为模式测试完成")
    print("="*60)

# ==================== 混淆和逃避技术 ====================

def evasion_techniques():
    """
    逃避检测的技术
    """
    print("\n[逃避技术演示]")
    
    # 1. 字符串混淆
    cmd_parts = ["who", "am", "i"]
    obfuscated_cmd = "".join(cmd_parts)
    print(f"混淆的命令: {obfuscated_cmd}")
    
    # 2. 编码
    encoded_command = base64.b64encode(b"dir").decode()
    print(f"Base64编码的命令: {encoded_command}")
    
    # 3. 延迟执行
    print("延迟执行（sleep 1秒）...")
    time.sleep(1)
    
    # 4. 条件执行
    if random.random() > 0.5:
        print("条件执行: 50%概率执行某些操作")
    
    # 5. 多阶段加载
    print("模拟多阶段加载: 下载->解密->执行")

# ==================== 主函数 ====================

def main():
    """
    主函数 - 控制漏洞测试流程
    """
    print("="*70)
    print("综合漏洞测试程序 v2.0")
    print("包含静态和动态漏洞示例")
    print("="*70)
    
    # 获取测试模式
    import sys
    test_mode = "normal"
    if len(sys.argv) > 1:
        test_mode = sys.argv[1].lower()
    
    print(f"\n测试模式: {test_mode}")
    print("警告：此程序仅用于授权的安全测试！")
    print("-"*70)
    
    # 动态漏洞测试
    print("\n[动态漏洞测试]")
    
    if test_mode in ["normal", "full", "dynamic"]:
        # 命令注入测试（使用安全参数）
        command_injection_vulnerable("127.0.0.1 -n 2")
        
        # 反序列化测试（使用安全数据）
        safe_data = pickle.dumps({"test": "data"})
        insecure_deserialization(safe_data)
        
        # 路径遍历测试（使用安全路径）
        path_traversal_vulnerable("test.txt")
    
    # 静态漏洞展示（始终显示）
    print("\n[静态漏洞展示]")
    
    # 显示硬编码信息（但不泄露真实值）
    print(f"硬编码API密钥长度: {len(API_KEY)}")
    print(f"硬编码数据库密码长度: {len(DATABASE_PASSWORD)}")
    print(f"硬编码加密密钥长度: {len(ENCRYPTION_KEY)}")
    
    # SQL注入模式展示
    sql_injection_vulnerable(1, "admin")
    
    # 弱加密展示
    weak_encryption_vulnerable("test_password")
    
    # 不安全的直接对象引用
    insecure_direct_object_reference(1)
    
    # 恶意行为模式测试
    if test_mode in ["full", "malicious"]:
        malicious_behavior_patterns()
    
    # 逃避技术展示
    if test_mode == "full":
        evasion_techniques()
    
    # 测试总结
    print("\n" + "="*70)
    print("[测试总结]")
    print("="*70)
    
    vulnerabilities = {
        "动态漏洞": [
            "1. 命令注入漏洞",
            "2. 不安全的反序列化",
            "3. 路径遍历漏洞"
        ],
        "静态漏洞": [
            "1. 硬编码敏感信息",
            "2. SQL注入漏洞模式",
            "3. 弱加密算法",
            "4. 不安全的直接对象引用"
        ],
        "恶意行为": [
            "1. 系统信息收集",
            "2. 网络连接测试",
            "3. 文件系统探测",
            "4. 进程信息收集",
            "5. 持久化机制",
            "6. 数据外传"
        ]
    }
    
    for category, vuln_list in vulnerabilities.items():
        print(f"\n{category}:")
        for vuln in vuln_list:
            print(f"  {vuln}")
    
    print("\n" + "="*70)
    print("测试完成")
    print("注意：实际环境中请勿运行未经授权的测试程序")
    print("="*70)

# ==================== 入口点 ====================

if __name__ == "__main__":
    # 添加命令行参数解析
    import argparse
    
    parser = argparse.ArgumentParser(
        description='综合漏洞测试程序',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python vuln_test.py normal    # 正常测试（推荐）
  python vuln_test.py full      # 完整测试（包含所有行为）
  python vuln_test.py dynamic   # 仅测试动态漏洞
  python vuln_test.py malicious # 测试恶意行为模式
  
警告：仅在授权的测试环境中使用！
        """
    )
    
    parser.add_argument(
        'mode',
        nargs='?',
        default='normal',
        choices=['normal', 'full', 'dynamic', 'malicious'],
        help='测试模式'
    )
    
    parser.add_argument(
        '--safe',
        action='store_true',
        help='安全模式（不执行实际命令）'
    )
    
    args = parser.parse_args()
    
    # 设置安全模式环境变量
    if args.safe:
        os.environ['SAFE_MODE'] = '1'
        print("[安全模式] 已启用，不执行实际命令")
    
    # 运行主函数
    main()
