
"""
伺服器偵測工具
偵測目標伺服器開放的端口和服務類型
⚠️ 僅用於測試自己的伺服器或已授權的系統
"""
import socket
import struct
import requests
import concurrent.futures
import time
import sys
from urllib.parse import urlparse

# ===== 配置區 =====
TARGET = "127.0.0.1"  # 可以是 IP 或域名
SCAN_COMMON_PORTS = True  # 掃描常見端口
SCAN_ALL_PORTS = False     # 掃描所有端口（0-65535，非常慢）
TIMEOUT = 1.0              # 連接超時時間（秒）
# ==================

# 常見服務端口
COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP Alt",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    8888: "HTTP Alt",
    27017: "MongoDB",
}

class ServerScanner:
    def __init__(self, target, timeout=1.0):
        self.target = target
        self.timeout = timeout
        self.results = {
            'tcp_open': [],
            'udp_open': [],
            'http_services': [],
            'banner_info': {}
        }
    
    def resolve_target(self):
        """解析域名到 IP"""
        try:
            ip = socket.gethostbyname(self.target)
            print(f"🌐 目標解析: {self.target} → {ip}\n")
            return ip
        except socket.gaierror:
            print(f"❌ 無法解析域名: {self.target}")
            return None
    
    def scan_tcp_port(self, ip, port):
        """掃描單個 TCP 端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # 嘗試抓取 banner
                banner = self.grab_banner(sock, port)
                sock.close()
                return port, True, banner
            
            sock.close()
            return port, False, None
        except:
            return port, False, None
    
    def grab_banner(self, sock, port):
        """嘗試抓取服務 banner"""
        try:
            # HTTP/HTTPS 服務
            if port in [80, 443, 8000, 8080, 8443, 8888]:
                sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner[:200]
            
            # 其他服務
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return banner[:200]
        except:
            return None
    
    def scan_udp_port(self, ip, port):
        """掃描單個 UDP 端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # 發送測試封包
            sock.sendto(b"\x00" * 10, (ip, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return port, True, data[:100]
            except socket.timeout:
                # UDP 超時不一定代表關閉
                sock.close()
                return port, None, None
        except:
            return port, False, None
    
    def detect_http_service(self, ip, port):
        """偵測 HTTP/HTTPS 服務詳情"""
        protocols = []
        
        # 嘗試 HTTP
        try:
            url = f"http://{ip}:{port}"
            response = requests.get(url, timeout=self.timeout, verify=False)
            protocols.append({
                'protocol': 'HTTP',
                'url': url,
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'headers': dict(response.headers)
            })
        except:
            pass
        
        # 嘗試 HTTPS
        try:
            url = f"https://{ip}:{port}"
            response = requests.get(url, timeout=self.timeout, verify=False)
            protocols.append({
                'protocol': 'HTTPS',
                'url': url,
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'headers': dict(response.headers)
            })
        except:
            pass
        
        return protocols
    
    def test_icmp(self, ip):
        """測試 ICMP (Ping)"""
        try:
            import subprocess
            import platform
            
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-W', '1', ip]
            
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
        except:
            return None
    
    def scan_ports(self, ip, ports):
        """並發掃描多個端口"""
        print(f"🔍 開始掃描 {len(ports)} 個端口...")
        print(f"⏱️  超時設定: {self.timeout} 秒\n")
        
        tcp_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(self.scan_tcp_port, ip, port) for port in ports]
            
            for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                port, is_open, banner = future.result()
                
                if is_open:
                    service = COMMON_PORTS.get(port, "Unknown")
                    tcp_results.append((port, service, banner))
                    print(f"✅ TCP {port:5d} - {service:20s} OPEN")
                    
                    if banner:
                        self.results['banner_info'][port] = banner
                
                # 進度顯示
                if i % 100 == 0:
                    sys.stdout.write(f"\r掃描進度: {i}/{len(ports)}")
                    sys.stdout.flush()
        
        print(f"\r掃描進度: {len(ports)}/{len(ports)} - 完成!\n")
        
        self.results['tcp_open'] = tcp_results
        return tcp_results
    
    def analyze_vulnerabilities(self, tcp_ports):
        """分析可能的攻擊向量"""
        print("\n" + "="*80)
        print("🎯 攻擊向量分析")
        print("="*80)
        
        vulnerabilities = []
        
        for port, service, banner in tcp_ports:
            # HTTP/HTTPS 服務
            if port in [80, 443, 8000, 8080, 8443, 8888]:
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'attacks': [
                        '✅ HTTP Request Flood (GET/POST)',
                        '✅ Slowloris 攻擊',
                        '✅ HTTP POST Slow 攻擊',
                        '⚠️  可能支援 HTTPS (SSL DDoS)',
                    ]
                })
            
            # SSH
            elif port == 22:
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'attacks': [
                        '✅ SYN Flood',
                        '⚠️  暴力破解 (慢速)',
                        '⚠️  SSH 連接耗盡',
                    ]
                })
            
            # DNS
            elif port == 53:
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'attacks': [
                        '✅ DNS 查詢 Flood',
                        '✅ DNS 放大攻擊 (如果是開放解析器)',
                    ]
                })
            
            # 資料庫
            elif port in [3306, 5432, 6379, 27017]:
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'attacks': [
                        '✅ SYN Flood',
                        '✅ 連接耗盡攻擊',
                        '⚠️  查詢 Flood',
                    ]
                })
            
            # 通用 TCP 服務
            else:
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'attacks': [
                        '✅ SYN Flood',
                        '✅ TCP 連接耗盡',
                    ]
                })
        
        for vuln in vulnerabilities:
            print(f"\n📍 端口 {vuln['port']} ({vuln['service']})")
            print("   可行的攻擊方式:")
            for attack in vuln['attacks']:
                print(f"   {attack}")
        
        return vulnerabilities
    
    def generate_report(self):
        """生成完整報告"""
        print("\n" + "="*80)
        print("📊 掃描報告")
        print("="*80)
        
        # TCP 端口摘要
        if self.results['tcp_open']:
            print(f"\n✅ 開放的 TCP 端口: {len(self.results['tcp_open'])} 個")
            print("-" * 80)
            for port, service, banner in self.results['tcp_open']:
                print(f"  端口 {port:5d} - {service:20s}")
                if banner:
                    # 顯示 banner 前 50 字元
                    banner_short = banner.replace('\n', ' ').replace('\r', '')[:50]
                    print(f"           Banner: {banner_short}...")
        else:
            print("\n❌ 沒有發現開放的 TCP 端口")
        
        # HTTP 服務詳情
        if self.results['http_services']:
            print(f"\n🌐 HTTP/HTTPS 服務:")
            print("-" * 80)
            for service in self.results['http_services']:
                print(f"  {service['protocol']:5s} {service['url']}")
                print(f"        狀態碼: {service['status_code']}")
                print(f"        伺服器: {service['server']}")
        
        print("\n" + "="*80)

def scan_url(url):
    """掃描 URL（用於測試公開網站）"""
    print("="*80)
    print("🌐 URL 掃描模式")
    print("="*80)
    
    parsed = urlparse(url if url.startswith('http') else f'http://{url}')
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    
    print(f"目標 URL: {url}")
    print(f"主機: {host}")
    print(f"端口: {port}")
    print(f"協議: {parsed.scheme.upper()}\n")
    
    scanner = ServerScanner(host)
    ip = scanner.resolve_target()
    
    if not ip:
        return
    
    # 測試 ICMP
    print("🔍 測試 ICMP (Ping)...")
    icmp_result = scanner.test_icmp(ip)
    if icmp_result:
        print("✅ ICMP 響應 - 可以使用 ICMP Flood\n")
    else:
        print("❌ ICMP 無響應 - 可能被防火牆阻擋\n")
    
    # 掃描目標端口
    print(f"🔍 掃描端口 {port}...")
    tcp_results = scanner.scan_ports(ip, [port])
    
    if tcp_results:
        # 偵測 HTTP 服務
        print("\n🔍 偵測 HTTP/HTTPS 服務...")
        http_services = scanner.detect_http_service(ip, port)
        scanner.results['http_services'] = http_services
        
        if http_services:
            for service in http_services:
                print(f"✅ {service['protocol']} 服務可用")
                print(f"   伺服器: {service['server']}")
                print(f"   狀態碼: {service['status_code']}")
        
        # 分析攻擊向量
        scanner.analyze_vulnerabilities(tcp_results)
    
    scanner.generate_report()

def scan_host(target, scan_mode="common"):
    """掃描主機"""
    print("="*80)
    print("🖥️  主機掃描模式")
    print("="*80)
    print(f"目標: {target}")
    print(f"模式: {scan_mode}\n")
    
    scanner = ServerScanner(target, TIMEOUT)
    ip = scanner.resolve_target()
    
    if not ip:
        return
    
    # 測試 ICMP
    print("🔍 測試 ICMP (Ping)...")
    icmp_result = scanner.test_icmp(ip)
    if icmp_result:
        print("✅ ICMP 響應 - 主機在線\n")
    elif icmp_result is False:
        print("❌ ICMP 無響應 - 主機可能離線或防火牆阻擋\n")
    else:
        print("⚠️  ICMP 測試失敗\n")
    
    # 選擇掃描端口
    if scan_mode == "common":
        ports = list(COMMON_PORTS.keys())
    elif scan_mode == "all":
        ports = range(1, 65536)
        print("⚠️  警告: 掃描所有端口需要很長時間！")
        confirm = input("是否繼續？(yes/no): ")
        if confirm.lower() != "yes":
            return
    else:
        ports = [int(p) for p in scan_mode.split(',')]
    
    # 掃描端口
    tcp_results = scanner.scan_ports(ip, ports)
    
    if tcp_results:
        # 偵測 HTTP 服務
        http_ports = [port for port, service, _ in tcp_results 
                     if port in [80, 443, 8000, 8080, 8443, 8888]]
        
        if http_ports:
            print(f"\n🔍 偵測 {len(http_ports)} 個 HTTP/HTTPS 端口...")
            for port in http_ports:
                http_services = scanner.detect_http_service(ip, port)
                scanner.results['http_services'].extend(http_services)
        
        # 分析攻擊向量
        scanner.analyze_vulnerabilities(tcp_results)
    else:
        print("❌ 沒有發現開放的端口")
    
    scanner.generate_report()

def main():
    print("\n" + "="*80)
    print("🔍 伺服器偵測工具")
    print("="*80)
    print("⚠️  警告: 未經授權的掃描是違法的！")
    print("   僅用於測試自己的伺服器或已授權的系統")
    print("="*80 + "\n")
    
    print("選擇掃描模式:")
    print("1. 掃描 URL (例: http://example.com)")
    print("2. 掃描主機 - 常見端口")
    print("3. 掃描主機 - 自訂端口")
    print("4. 掃描主機 - 所有端口 (1-65535, 很慢)")
    print("5. 快速測試本地伺服器 (127.0.0.1:8000)")
    
    choice = input("\n選擇 (1-5): ").strip()
    
    if choice == "1":
        target = input("輸入 URL (例: http://example.com:8000): ").strip()
        scan_url(target)
    
    elif choice == "2":
        target = input("輸入主機 IP 或域名: ").strip()
        scan_host(target, "common")
    
    elif choice == "3":
        target = input("輸入主機 IP 或域名: ").strip()
        ports = input("輸入端口 (用逗號分隔，例: 80,443,8000): ").strip()
        scan_host(target, ports)
    
    elif choice == "4":
        target = input("輸入主機 IP 或域名: ").strip()
        scan_host(target, "all")
    
    elif choice == "5":
        print("\n🚀 快速測試本地伺服器...")
        scan_host("127.0.0.1", "8000")
    
    else:
        print("❌ 無效選擇")

if __name__ == "__main__":
    main()