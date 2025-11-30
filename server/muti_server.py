
"""
多協議 DDoS 監測伺服器
同時監聽 TCP、UDP、ICMP 等多種協議
記錄各種攻擊嘗試
"""
import socket
import threading
import time
import struct
from collections import Counter, deque
from datetime import datetime
import json
import platform

try:
    import ctypes
except ImportError:
    ctypes = None

# ===== 配置區 =====
TCP_PORT = 8000      # TCP (HTTP) 端口
UDP_PORT = 9001      # UDP 端口 (避開 8001 常見衝突)
DNS_PORT = 53        # DNS 端口 (需要 root)
MONITOR_ICMP = True  # 是否監控 ICMP (需要 root)
# ==================

class AttackMonitor:
    """攻擊監控統計"""
    def __init__(self):
        self.stats = {
            'tcp_connections': 0,
            'tcp_syn': 0,
            'tcp_rst': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_requests': 0,
            'dns_queries': 0,
        }
        self.attack_types = Counter()
        self.source_ips = Counter()
        self.recent_attacks = deque(maxlen=100)
        self.lock = threading.Lock()
        self.start_time = time.time()
    
    def record_attack(self, attack_type, source_ip, details=""):
        """記錄攻擊事件"""
        with self.lock:
            self.attack_types[attack_type] += 1
            self.source_ips[source_ip] += 1
            
            event = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'type': attack_type,
                'source': source_ip,
                'details': details
            }
            self.recent_attacks.append(event)
    
    def increment_stat(self, stat_name):
        """增加統計計數"""
        with self.lock:
            if stat_name in self.stats:
                self.stats[stat_name] += 1
    
    def get_summary(self):
        """獲取統計摘要"""
        with self.lock:
            elapsed = time.time() - self.start_time
            return {
                'uptime': elapsed,
                'stats': dict(self.stats),
                'attack_types': dict(self.attack_types.most_common(10)),
                'top_attackers': dict(self.source_ips.most_common(10)),
                'recent_attacks': list(self.recent_attacks)[-20:]
            }
    
    def print_summary(self):
        """打印統計摘要"""
        summary = self.get_summary()
        
        print("\n" + "="*80)
        print(f"📊 攻擊監控摘要 (運行時間: {summary['uptime']:.0f} 秒)")
        print("="*80)
        
        print("\n📈 協議統計:")
        for stat, count in summary['stats'].items():
            if count > 0:
                print(f"  {stat:20s}: {count:,}")
        
        if summary['attack_types']:
            print("\n🎯 攻擊類型統計:")
            for attack_type, count in summary['attack_types'].items():
                print(f"  {attack_type:30s}: {count:,}")
        
        if summary['top_attackers']:
            print("\n🔴 Top 攻擊來源 IP:")
            for ip, count in summary['top_attackers'].items():
                print(f"  {ip:15s}: {count:,} 次")
        
        print("="*80)

monitor = AttackMonitor()

# ==================== TCP 監聽器 ====================
class TCPListener:
    """TCP 連接監聽器"""
    
    @staticmethod
    def handle_client(client_socket, client_address):
        """處理單個 TCP 連接"""
        try:
            monitor.increment_stat('tcp_connections')
            
            # 設定短超時來檢測攻擊
            client_socket.settimeout(2.0)
            
            try:
                # 嘗試接收數據
                data = client_socket.recv(1024)
                
                if not data:
                    # 空連接 - 可能是 SYN Flood 或連接掃描
                    monitor.record_attack(
                        "TCP Empty Connection",
                        client_address[0],
                        "連接後立即斷開，可能是 SYN Flood 或端口掃描"
                    )
                    return
                
                # 檢查是否是 HTTP 請求
                if data.startswith(b'GET') or data.startswith(b'POST') or \
                   data.startswith(b'PUT') or data.startswith(b'DELETE'):
                    monitor.increment_stat('http_requests')
                    
                    # 解析 HTTP 方法
                    method = data.split(b' ')[0].decode('utf-8', errors='ignore')
                    monitor.record_attack(
                        f"HTTP {method} Request",
                        client_address[0],
                        f"收到 HTTP 請求，大小 {len(data)} bytes"
                    )
                    
                    # 發送簡單響應
                    response = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nLogged\n"
                    client_socket.send(response)
                
                else:
                    # 非 HTTP 數據
                    monitor.record_attack(
                        "TCP Raw Data",
                        client_address[0],
                        f"收到非 HTTP 數據，大小 {len(data)} bytes"
                    )
            
            except socket.timeout:
                # 超時 - 可能是 Slowloris 攻擊
                monitor.record_attack(
                    "Slowloris Attack",
                    client_address[0],
                    "連接建立後長時間不發送數據，疑似 Slowloris"
                )
        
        except Exception as e:
            monitor.record_attack(
                "TCP Error",
                client_address[0],
                f"處理連接時出錯: {type(e).__name__}"
            )
        
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    @staticmethod
    def start(port):
        """啟動 TCP 監聽"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(100)
            
            print(f"✅ TCP 監聽器啟動於端口 {port}")
            
            while True:
                try:
                    client_socket, client_address = server_socket.accept()
                    
                    # 每個連接用新線程處理
                    thread = threading.Thread(
                        target=TCPListener.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    thread.start()
                
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"TCP 監聽器錯誤: {e}")
        
        except Exception as e:
            print(f"❌ 無法啟動 TCP 監聽器: {e}")

# ==================== UDP 監聽器 ====================
class UDPListener:
    """UDP 封包監聽器"""
    
    @staticmethod
    def start(port):
        """啟動 UDP 監聽"""
        max_retries = 10
        original_port = port
        
        for attempt in range(max_retries):
            try:
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                udp_socket.bind(('0.0.0.0', port))
                
                if port != original_port:
                    print(f"✅ UDP 監聽器啟動於端口 {port} (原 {original_port} 已被佔用)")
                else:
                    print(f"✅ UDP 監聽器啟動於端口 {port}")
                
                while True:
                    try:
                        data, addr = udp_socket.recvfrom(65535)
                        monitor.increment_stat('udp_packets')
                        
                        source_ip = addr[0]
                        
                        # 檢查是否是 DNS 查詢
                        if len(data) > 12 and port == 53:
                            monitor.increment_stat('dns_queries')
                            monitor.record_attack(
                                "DNS Query",
                                source_ip,
                                f"DNS 查詢，大小 {len(data)} bytes"
                            )
                        else:
                            # 普通 UDP 封包
                            monitor.record_attack(
                                "UDP Packet",
                                source_ip,
                                f"UDP 封包，大小 {len(data)} bytes"
                            )
                        
                        # 檢測 UDP Flood
                        if monitor.source_ips[source_ip] > 100:
                            monitor.record_attack(
                                "UDP Flood Detected",
                                source_ip,
                                f"來自同一來源的大量 UDP 封包 ({monitor.source_ips[source_ip]} 個)"
                            )
                    
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        print(f"UDP 監聽器錯誤: {e}")
                
                # 成功綁定並運行，跳出重試迴圈
                break
            
            except OSError as e:
                if e.errno == 10048 or 'address already in use' in str(e).lower():
                    # 端口被佔用，嘗試下一個
                    port += 1
                    if attempt == max_retries - 1:
                        print(f"❌ 無法啟動 UDP 監聽器: 端口 {original_port}-{port} 都已被佔用")
                        return
                else:
                    print(f"❌ 無法啟動 UDP 監聽器: {e}")
                    return
            except Exception as e:
                print(f"❌ 無法啟動 UDP 監聽器: {e}")
                return

# ==================== ICMP 監聽器 ====================
class ICMPListener:
    """ICMP 封包監聽器 (需要 root 權限)"""
    
    @staticmethod
    def parse_icmp(data):
        """解析 ICMP 封包"""
        try:
            # IP 標頭 (前 20 bytes)
            ip_header = data[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            source_ip = socket.inet_ntoa(iph[8])
            
            # ICMP 標頭
            icmp_header = data[20:28]
            icmph = struct.unpack('!BBHHH', icmp_header)
            
            icmp_type = icmph[0]
            icmp_code = icmph[1]
            
            return source_ip, icmp_type, icmp_code
        except:
            return None, None, None
    
    @staticmethod
    def start():
        """啟動 ICMP 監聽"""
        def is_admin():
            if ctypes is None:
                return False
            try:
                if platform.system() == 'Windows':
                    return ctypes.windll.shell32.IsUserAnAdmin() != 0
                else:
                    return os.geteuid() == 0  # type: ignore
            except:
                return False

        system = platform.system()
        if system == 'Windows':
            # Windows 使用 IP 原始套接字 + SIO_RCVALL 捕獲所有 IP 封包，手動過濾 ICMP
            try:
                if not is_admin():
                    print("⚠️  ICMP 監聽器：需要以管理員身份執行 (Windows)")
                    return
                host_ip = socket.gethostbyname(socket.gethostname())
                sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sniffer.bind((host_ip, 0))
                sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # 啟用混雜模式 (接收所有封包)
                SIO_RCVALL = 0x98000001
                sniffer.ioctl(SIO_RCVALL, socket.RCVALL_ON)
                print(f"✅ ICMP 監聽器 (Windows) 已啟動，介面 IP: {host_ip}")
                while True:
                    try:
                        raw_data, addr = sniffer.recvfrom(65535)
                        # 解析 IP 標頭
                        if len(raw_data) < 34:
                            continue
                        ip_header = raw_data[:20]
                        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                        protocol = iph[6]
                        source_ip = socket.inet_ntoa(iph[8])
                        if protocol == 1:  # ICMP
                            monitor.increment_stat('icmp_packets')
                            icmp_header = raw_data[20:28]
                            try:
                                icmph = struct.unpack('!BBHHH', icmp_header)
                                icmp_type = icmph[0]
                            except:
                                icmp_type = None
                            if icmp_type == 8:
                                monitor.record_attack("ICMP Echo Request (Ping)", source_ip, "Ping 請求")
                            else:
                                monitor.record_attack("ICMP Packet", source_ip, f"ICMP 類型 {icmp_type}")
                            if monitor.source_ips[source_ip] > 50:
                                monitor.record_attack("ICMP Flood Detected", source_ip, "大量 ICMP 封包")
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        print(f"ICMP 監聽器錯誤: {e}")
            except Exception as e:
                print(f"❌ 無法啟動 ICMP 監聽器 (Windows): {e}")
            finally:
                try:
                    sniffer.ioctl(SIO_RCVALL, socket.RCVALL_OFF)  # 關閉混雜模式
                except:
                    pass
        else:
            # Linux/macOS: 使用 IPPROTO_ICMP
            try:
                if not is_admin():
                    print("⚠️  ICMP 監聽器：需要 root 權限 (sudo) 才能捕獲 ICMP")
                    return
                icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                print("✅ ICMP 監聽器 (Unix) 已啟動")
                while True:
                    try:
                        data, addr = icmp_socket.recvfrom(65535)
                        monitor.increment_stat('icmp_packets')
                        source_ip, icmp_type, icmp_code = ICMPListener.parse_icmp(data)
                        if source_ip:
                            if icmp_type == 8:
                                monitor.record_attack("ICMP Echo Request (Ping)", source_ip, "Ping 請求")
                            else:
                                monitor.record_attack("ICMP Packet", source_ip, f"ICMP 類型 {icmp_type}")
                            if monitor.source_ips[source_ip] > 50:
                                monitor.record_attack("ICMP Flood Detected", source_ip, "大量 ICMP 封包")
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        print(f"ICMP 監聽器錯誤: {e}")
            except Exception as e:
                print(f"❌ 無法啟動 ICMP 監聽器 (Unix): {e}")

# ==================== SYN Flood 檢測器 ====================
class SYNFloodDetector:
    """
    SYN Flood 檢測器
    注意: 這需要更底層的封包捕獲（如 pcap）
    這裡提供簡化版本
    """
    
    @staticmethod
    def start(port):
        """
        監控 TCP 連接狀態
        這是簡化版本，真實環境建議使用 scapy 或 pcap
        """
        print(f"⚠️  SYN Flood 檢測器 (簡化版)")
        print(f"   建議安裝 scapy 進行完整的封包分析")
        
        # 這裡可以添加更複雜的 SYN 檢測邏輯
        # 例如使用 scapy 捕獲 TCP SYN 封包

# ==================== 統計報告線程 ====================
def print_stats_periodically():
    """定期打印統計資訊"""
    while True:
        time.sleep(10)  # 每 10 秒打印一次
        monitor.print_summary()

# ==================== 主程式 ====================
def main():
    print("="*80)
    print("🛡️  多協議 DDoS 監測伺服器")
    print("="*80)
    print("此伺服器會監聽多種協議的攻擊:")
    print("  - TCP 連接 (HTTP, Slowloris, SYN Flood)")
    print("  - UDP 封包 (UDP Flood, DNS Flood)")
    print("  - ICMP 封包 (Ping Flood)")
    print("="*80 + "\n")
    
    threads = []
    
    # 啟動 TCP 監聽器
    tcp_thread = threading.Thread(target=TCPListener.start, args=(TCP_PORT,), daemon=True)
    tcp_thread.start()
    threads.append(tcp_thread)
    time.sleep(0.5)
    
    # 啟動 UDP 監聽器
    udp_thread = threading.Thread(target=UDPListener.start, args=(UDP_PORT,), daemon=True)
    udp_thread.start()
    threads.append(udp_thread)
    time.sleep(0.5)
    
    # 嘗試啟動 DNS 監聽器 (需要 root)
    try:
        dns_thread = threading.Thread(target=UDPListener.start, args=(DNS_PORT,), daemon=True)
        dns_thread.start()
        threads.append(dns_thread)
        time.sleep(0.5)
    except:
        print(f"⚠️  無法啟動 DNS 監聽器 (端口 53 需要 root 權限)")
    
    # 啟動 ICMP 監聽器 (需要 root)
    if MONITOR_ICMP:
        icmp_thread = threading.Thread(target=ICMPListener.start, daemon=True)
        icmp_thread.start()
        threads.append(icmp_thread)
        time.sleep(0.5)
    
    # 啟動統計報告線程
    stats_thread = threading.Thread(target=print_stats_periodically, daemon=True)
    stats_thread.start()
    
    print("\n" + "="*80)
    print("✅ 所有監聽器已啟動")
    print("="*80)
    print("📊 即時監控:")
    print(f"  - TCP 端口: {TCP_PORT}")
    print(f"  - UDP 端口: {UDP_PORT}")
    if MONITOR_ICMP:
        print(f"  - ICMP: 已啟用")
    print("\n💡 使用攻擊工具測試各種攻擊方式")
    print("   按 Ctrl+C 停止並查看完整報告\n")
    print("="*80 + "\n")
    
    try:
        # 主線程保持運行
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n\n⏹️  正在關閉伺服器...")
        
        # 生成最終報告
        monitor.print_summary()
        
        print("\n✅ 伺服器已關閉\n")

if __name__ == '__main__':
    main()