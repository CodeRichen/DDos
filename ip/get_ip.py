"""
獲取本機真實IP地址的工具
"""
import socket

def get_local_ip():
    """獲取本機局域網IP地址"""
    try:
        # 創建一個UDP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 連接到外部地址(不會真正發送數據)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def get_all_ips():
    """獲取所有可用的IP地址"""
    hostname = socket.gethostname()
    try:
        # 獲取所有IP地址
        ips = socket.gethostbyname_ex(hostname)[2]
        return [ip for ip in ips if not ip.startswith("127.")]
    except:
        return []

if __name__ == '__main__':
    print("本機IP信息:")
    print(f"  主機名: {socket.gethostname()}")
    print(f"  主要IP: {get_local_ip()}")
    print(f"  所有IP: {get_all_ips()}")
    print(f"\n推薦使用: http://{get_local_ip()}:8000")
