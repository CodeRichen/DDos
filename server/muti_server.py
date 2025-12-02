
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
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import hashlib
import base64
import psutil

try:
    import ctypes
except ImportError:
    ctypes = None

# ===== 配置區 =====
TCP_PORT = 8000      # TCP (攻擊監聽) 端口
UDP_PORT = 9001      # UDP 端口 (避開 8001 常見衝突)
DNS_PORT = 53        # DNS 端口 (需要 root)
MONITOR_ICMP = True  # 是否監控 ICMP (需要 root)
WEB_PORT = 8888      # 網頁介面端口
# ==================

# ===== 封包分析函數 =====
def analyze_packet_requirements(method, path, headers, protocol='TCP'):
    """
    分析封包要求伺服器執行的底層操作
    返回操作列表和封包特徵
    """
    operations = []
    features = {
        'protocol': protocol,
        'method': method,
        'path_type': 'other',
        'requires_parsing': False,
        'requires_processing': False,
        'requires_response': True,
    }
    
    if protocol == 'TCP' or protocol == 'HTTP':
        # 1. TCP 連接層操作
        operations.append("[TCP層] 接受客戶端連接 (三次握手已完成)")
        operations.append("[TCP層] 從 socket 讀取數據流")
        
        # 2. HTTP 協議層操作
        if method:
            operations.append(f"[HTTP層] 解析請求行: {method} {path} HTTP/1.1")
            operations.append(f"[HTTP層] 解析請求標頭 ({len(headers)} 個欄位)")
        
        # 分析標頭內容
        if 'Content-Length' in headers:
            content_len = headers.get('Content-Length', '0')
            operations.append(f"[HTTP層] 準備接收請求主體 ({content_len} bytes)")
            features['requires_parsing'] = True
        
        if 'Connection' in headers:
            conn_type = headers.get('Connection', 'keep-alive')
            operations.append(f"[HTTP層] 連接管理: {conn_type}")
        
        # 3. 路徑分析與路由
        if path == '/' or path == '':
            features['path_type'] = 'root'
            operations.append("[路由] 匹配根路徑 '/'")
            operations.append("[處理] 生成 HTTP 響應")
            features['requires_processing'] = True
        elif path == '/favicon.ico':
            features['path_type'] = 'favicon'
            operations.append("[路由] 匹配 favicon 請求")
            operations.append("[處理] 返回 204 No Content")
        else:
            features['path_type'] = 'other'
            operations.append(f"[路由] 處理路徑: {path}")
            operations.append("[處理] 生成響應")
        
        # 4. 方法特定操作
        if method == 'GET':
            operations.append("[方法] GET - 只讀操作")
        elif method == 'POST':
            operations.append("[方法] POST - 創建資源")
            operations.append("[處理] 解析請求主體數據")
            features['requires_parsing'] = True
        elif method == 'PUT':
            operations.append("[方法] PUT - 更新資源")
            operations.append("[處理] 解析請求主體數據")
            features['requires_parsing'] = True
        elif method == 'DELETE':
            operations.append("[方法] DELETE - 刪除資源")
        
        # 5. 監控與響應
        operations.append("[監控] 記錄攻擊事件")
        operations.append("[監控] 更新統計計數器")
        operations.append("[響應] 構建 HTTP 響應")
        operations.append("[TCP層] 將響應寫入 socket")
        operations.append("[TCP層] 關閉連接或保持活動")
    
    elif protocol == 'UDP':
        operations.append("[UDP層] 接收數據包")
        operations.append("[UDP層] 解析數據包內容")
        operations.append("[監控] 記錄 UDP 封包")
        operations.append("[監控] 更新統計計數器")
        features['requires_response'] = False
    
    elif protocol == 'ICMP':
        operations.append("[ICMP層] 捕獲 ICMP 封包")
        operations.append("[ICMP層] 解析 ICMP 類型和代碼")
        operations.append("[監控] 識別 ICMP 攻擊類型")
        operations.append("[監控] 更新統計計數器")
        features['requires_response'] = False
    
    return operations, features

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
        self.recent_attacks = deque(maxlen=5)  # 保留最近 5 條
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.process = psutil.Process()  # 當前進程
    
    def record_attack(self, attack_type, source_ip, details="", operations=None, features=None):
        """記錄攻擊事件（含底層操作）"""
        with self.lock:
            self.attack_types[attack_type] += 1
            self.source_ips[source_ip] += 1
            
            event = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'type': attack_type,
                'source': source_ip,
                'details': details,
                'operations': operations or [],
                'features': features or {}
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
            # 返回所有 50 條攻擊記錄
            recent = list(self.recent_attacks)
            
            # 獲取系統資源（只計算當前進程）
            try:
                # 當前進程的 CPU 使用率
                cpu_percent = self.process.cpu_percent(interval=0.1)
                # 當前進程的記憶體使用
                memory_info = self.process.memory_info()
                memory_percent = (memory_info.rss / psutil.virtual_memory().total) * 100
                # 網路統計（全局）
                net_io = psutil.net_io_counters()
                net_sent_kb = net_io.bytes_sent / 1024
                net_recv_kb = net_io.bytes_recv / 1024
            except:
                cpu_percent = 0
                memory_percent = 0
                net_sent_kb = 0
                net_recv_kb = 0
            
            return {
                'uptime': elapsed,
                'stats': dict(self.stats),
                'attack_types': dict(self.attack_types.most_common(10)),
                'top_attackers': dict(self.source_ips.most_common(10)),
                'recent_attacks': recent,
                'system': {
                    'cpu': cpu_percent,
                    'memory': memory_percent,
                    'net_sent': net_sent_kb,
                    'net_recv': net_recv_kb
                }
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
                    operations, features = analyze_packet_requirements('', '', {}, 'TCP')
                    monitor.record_attack(
                        "TCP Empty Connection",
                        client_address[0],
                        "連接後立即斷開，可能是 SYN Flood 或端口掃描",
                        operations=operations,
                        features=features
                    )
                    return
                
                # 檢查是否是 HTTP 請求
                if data.startswith(b'GET') or data.startswith(b'POST') or \
                   data.startswith(b'PUT') or data.startswith(b'DELETE'):
                    monitor.increment_stat('http_requests')
                    
                    # 解析 HTTP 方法和路徑
                    try:
                        request_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                        parts = request_line.split(' ')
                        method = parts[0] if len(parts) > 0 else 'GET'
                        path = parts[1] if len(parts) > 1 else '/'
                        
                        # 解析標頭
                        headers = {}
                        header_lines = data.split(b'\r\n')[1:]
                        for line in header_lines:
                            if b':' in line:
                                try:
                                    key, value = line.decode('utf-8', errors='ignore').split(':', 1)
                                    headers[key.strip()] = value.strip()
                                except:
                                    pass
                    except:
                        method = 'GET'
                        path = '/'
                        headers = {}
                    
                    # 分析封包底層操作
                    operations, features = analyze_packet_requirements(method, path, headers, 'HTTP')
                    
                    monitor.record_attack(
                        f"HTTP {method} Request",
                        client_address[0],
                        f"收到 HTTP 請求，大小 {len(data)} bytes",
                        operations=operations,
                        features=features
                    )
                    
                    # 發送簡單響應
                    response = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nLogged\n"
                    client_socket.send(response)
                
                else:
                    # 非 HTTP 數據
                    operations, features = analyze_packet_requirements('', '', {}, 'TCP')
                    monitor.record_attack(
                        "TCP Raw Data",
                        client_address[0],
                        f"收到非 HTTP 數據，大小 {len(data)} bytes",
                        operations=operations,
                        features=features
                    )
            
            except socket.timeout:
                # 超時 - 可能是 Slowloris 攻擊
                operations = [
                    "[TCP層] 接受客戶端連接",
                    "[TCP層] 等待數據 (timeout=2.0s)",
                    "[檢測] 超時 - 疑似 Slowloris 攻擊",
                    "[監控] 記錄慢速攻擊事件",
                    "[TCP層] 強制關閉連接"
                ]
                features = {'protocol': 'TCP', 'attack_pattern': 'slowloris'}
                monitor.record_attack(
                    "Slowloris Attack",
                    client_address[0],
                    "連接建立後長時間不發送數據，疑似 Slowloris",
                    operations=operations,
                    features=features
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
                            operations = [
                                "[UDP層] 接收 DNS 數據包",
                                "[DNS層] 解析 DNS 查詢標頭",
                                "[DNS層] 提取查詢域名",
                                "[監控] 記錄 DNS 查詢事件",
                                "[監控] 更新統計計數器"
                            ]
                            features = {'protocol': 'DNS', 'size': len(data)}
                            monitor.record_attack(
                                "DNS Query",
                                source_ip,
                                f"DNS 查詢，大小 {len(data)} bytes",
                                operations=operations,
                                features=features
                            )
                        else:
                            # 普通 UDP 封包
                            operations = [
                                "[UDP層] 接收數據包",
                                "[UDP層] 驗證數據包完整性",
                                "[監控] 記錄 UDP 封包",
                                "[監控] 更新統計計數器"
                            ]
                            features = {'protocol': 'UDP', 'size': len(data)}
                            monitor.record_attack(
                                "UDP Packet",
                                source_ip,
                                f"UDP 封包，大小 {len(data)} bytes",
                                operations=operations,
                                features=features
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

# ==================== WebSocket 處理器 ====================
websocket_clients = []
websocket_lock = threading.Lock()

class WebSocketHandler(SimpleHTTPRequestHandler):
    """HTTP + WebSocket 處理器"""
    
    def do_GET(self):
        """處理 HTTP GET 請求"""
        if self.path == '/':
            self.path = '/templates/attack_monitor.html'
        elif self.path == '/ws':
            self.handle_websocket()
            return
        
        # 處理靜態文件
        if self.path.startswith('/templates/'):
            try:
                file_path = os.path.join(os.path.dirname(__file__), self.path.lstrip('/'))
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    self.send_response(200)
                    if file_path.endswith('.html'):
                        self.send_header('Content-type', 'text/html; charset=utf-8')
                    elif file_path.endswith('.css'):
                        self.send_header('Content-type', 'text/css')
                    elif file_path.endswith('.js'):
                        self.send_header('Content-type', 'application/javascript')
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self.send_error(404)
            except Exception as e:
                print(f"文件讀取錯誤: {e}")
                self.send_error(500)
        else:
            self.send_error(404)
    
    def handle_websocket(self):
        """處理 WebSocket 升級"""
        try:
            key = self.headers.get('Sec-WebSocket-Key')
            if not key:
                self.send_error(400, 'Bad Request')
                return
            
            magic = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            accept_key = base64.b64encode(
                hashlib.sha1((key + magic).encode()).digest()
            ).decode()
            
            self.send_response(101, 'Switching Protocols')
            self.send_header('Upgrade', 'websocket')
            self.send_header('Connection', 'Upgrade')
            self.send_header('Sec-WebSocket-Accept', accept_key)
            self.end_headers()
            
            with websocket_lock:
                websocket_clients.append(self.connection)
            
            print(f"✅ WebSocket 客戶端已連接，當前連接數: {len(websocket_clients)}")
            
            # 保持連接打開 - 使用阻塞模式但設置超時
            self.connection.setblocking(True)
            self.connection.settimeout(None)  # 無超時，保持連接
            
            try:
                # 持續讀取，直到連接關閉
                while True:
                    try:
                        # 接收數據（阻塞式）
                        data = self.connection.recv(1024, socket.MSG_PEEK)
                        if not data:
                            # 連接已關閉
                            break
                        # 實際讀取數據
                        self.connection.recv(1024)
                    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
                        # 連接錯誤
                        break
                    except Exception:
                        break
            except KeyboardInterrupt:
                pass
        
        except Exception as e:
            print(f"WebSocket 錯誤: {e}")
        finally:
            with websocket_lock:
                if self.connection in websocket_clients:
                    websocket_clients.remove(self.connection)
            print(f"WebSocket 客戶端已斷開，當前連接數: {len(websocket_clients)}")
    
    def log_message(self, format, *args):
        """靜默日誌"""
        pass

def broadcast_stats():
    """定期廣播統計數據給所有 WebSocket 客戶端"""
    print("📡 WebSocket 廣播線程已啟動")
    last_broadcast = 0
    while True:
        try:
            time.sleep(1)
            
            if len(websocket_clients) == 0:
                continue
            
            summary = monitor.get_summary()
            data = json.dumps(summary).encode('utf-8')
            
            # 每 10 秒打印一次狀態
            current_time = time.time()
            if current_time - last_broadcast >= 10:
                print(f"📤 廣播: TCP={summary['stats']['tcp_connections']}, 客戶端={len(websocket_clients)}")
                last_broadcast = current_time
            
            frame = bytearray()
            frame.append(0x81)
            
            payload_len = len(data)
            if payload_len < 126:
                frame.append(payload_len)
            elif payload_len < 65536:
                frame.append(126)
                frame.extend(payload_len.to_bytes(2, 'big'))
            else:
                frame.append(127)
                frame.extend(payload_len.to_bytes(8, 'big'))
            
            frame.extend(data)
            
            with websocket_lock:
                disconnected = []
                for client in websocket_clients:
                    try:
                        client.sendall(bytes(frame))
                    except:
                        disconnected.append(client)
                
                for client in disconnected:
                    websocket_clients.remove(client)
        
        except Exception as e:
            print(f"廣播錯誤: {e}")

def start_web_server(port):
    """啟動網頁伺服器"""
    try:
        server = HTTPServer(('0.0.0.0', port), WebSocketHandler)
        print(f"✅ 網頁介面啟動於 http://0.0.0.0:{port}")
        print(f"   在瀏覽器中打開: http://localhost:{port}")
        server.serve_forever()
    except Exception as e:
        print(f"❌ 無法啟動網頁伺服器: {e}")

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
    
    # 啟動網頁伺服器
    web_thread = threading.Thread(target=start_web_server, args=(WEB_PORT,), daemon=True)
    web_thread.start()
    threads.append(web_thread)
    time.sleep(0.5)
    
    # 啟動 WebSocket 廣播
    broadcast_thread = threading.Thread(target=broadcast_stats, daemon=True)
    broadcast_thread.start()
    threads.append(broadcast_thread)
    time.sleep(0.5)
    
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
    print(f"  - 攻擊監聽 TCP: {TCP_PORT}")
    print(f"  - 攻擊監聽 UDP: {UDP_PORT}")
    if MONITOR_ICMP:
        print(f"  - ICMP: 已啟用")
    print(f"  - 網頁介面: http://localhost:{WEB_PORT}")
    print("\n💡 打開瀏覽器訪問網頁介面查看即時數據")
    print("   使用攻擊工具測試各種攻擊方式")
    print("   按 Ctrl+C 停止伺服器\n")
    print("="*80 + "\n")
    
    try:
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n\n⏹️  正在關閉伺服器...")
        monitor.print_summary()
        print("\n✅ 伺服器已關閉\n")

if __name__ == '__main__':
    main()