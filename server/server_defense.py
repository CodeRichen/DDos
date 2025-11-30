# -*- coding: utf-8 -*-
"""
進階防禦伺服器 - 包含多種 DDoS 防禦機制
僅用於教育目的和本地測試
現已支持同時監聽 TCP (HTTP) 和 UDP 流量
"""
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import ThreadingMixIn, UDPServer, BaseRequestHandler
import socket
import time
import threading
from collections import defaultdict, deque
import hashlib
import json

# 導入監控模組和模板渲染模組
import server_monitor
import template_renderer

# 全局統計
request_count = 0
blocked_count = 0
start_time = time.time()
request_lock = threading.Lock()

# 最近的請求日誌 (保留最近 50 條)
recent_requests = deque(maxlen=50)
requests_log_lock = threading.Lock()

# 用於計算即時請求速率的時間窗口
request_timestamps = deque(maxlen=1000)
timestamps_lock = threading.Lock()

# 用於計算允許通過的請求速率的時間窗口（只計算通過防禦的請求）
allowed_timestamps = deque(maxlen=1000)
allowed_timestamps_lock = threading.Lock()

def get_request_count():
    """獲取當前請求總數"""
    with request_lock:
        return request_count

def get_recent_request_rate():
    """計算最近 10 秒的請求速率（只計算允許通過的請求）"""
    current_time = time.time()
    time_window = 10.0
    
    with allowed_timestamps_lock:
        while allowed_timestamps and current_time - allowed_timestamps[0] > time_window:
            allowed_timestamps.popleft()
        
        count = len(allowed_timestamps)
        if count == 0:
            return 0.0
        
        actual_window = current_time - allowed_timestamps[0] if count > 0 else time_window
        return count / actual_window if actual_window > 0 else 0.0

# 攔截日誌
block_logs = deque(maxlen=100)  # 保留最近100條攔截記錄
block_reasons = defaultdict(int)  # 統計各種攔截原因

# 防禦機制配置
defense_config = {
    'rate_limiting': True,      # 速率限制
    'ip_blacklist': True,       # IP 黑名單
    'connection_limit': True,   # 連接數限制
    'challenge_response': False, # 挑戰-響應 (簡化版)
    'request_validation': True,  # 請求驗證
    'adaptive_delay': True,      # 自適應延遲
}

# UDP 洪泛處理器
class UDPFloodHandler(BaseRequestHandler):
    """處理 UDP 洪泛攻擊 - 應用防禦機制"""
    packet_count = 0
    count_lock = threading.Lock()
    defense_system = None  # 將在 run_server 中設置
    last_log_time = time.time()
    
    def handle(self):
        global request_count, blocked_count
        
        try:
            data = self.request[0]  # UDP 數據包
            client_ip = self.client_address[0]
            
            # 增加計數
            with self.count_lock:
                UDPFloodHandler.packet_count += 1
                packet_num = UDPFloodHandler.packet_count
                # 每次都檢查是否需要打印（減少鎖爭用）
                should_log = (packet_num % 100 == 0)
            
            # 增加全局請求計數
            with request_lock:
                request_count += 1
            
            # 應用防禦邏輯
            is_blocked = False
            block_reason = None
            
            # 調試：檢查防禦系統是否被初始化
            if not UDPFloodHandler.defense_system:
                # 防禦系統未初始化，記錄警告
                try:
                    with open('server_log.txt', 'a', encoding='utf-8') as f:
                        f.write(f"[警告] UDP 處理器中防禦系統為 None (包 #{packet_num})\n")
                except:
                    pass
            
            if UDPFloodHandler.defense_system:
                # 檢查是否應該攔截
                try:
                    should_block, reason = UDPFloodHandler.defense_system.check_request(
                        client_ip, 
                        'UDP', 
                        '/udp_flood'
                    )
                    
                    if should_block:
                        is_blocked = True
                        block_reason = reason
                        with request_lock:
                            blocked_count += 1
                        
                        # 記錄攔截到防禦系統
                        UDPFloodHandler.defense_system.log_block(
                            client_ip,
                            reason,
                            {'packet_size': len(data), 'protocol': 'UDP'}
                        )
                    else:
                        # 記錄允許通過的請求時間戳
                        with allowed_timestamps_lock:
                            allowed_timestamps.append(time.time())
                except Exception as defense_error:
                    # 防禦檢查出錯，記錄錯誤信息（用於調試）
                    try:
                        with open('server_log.txt', 'a', encoding='utf-8') as f:
                            f.write(f"[錯誤] UDP 防禦檢查失敗: {str(defense_error)[:100]}\n")
                    except:
                        pass
            
            # 定期記錄統計（避免頻繁 I/O）
            if should_log:
                try:
                    with open('server_log.txt', 'a', encoding='utf-8') as f:
                        status = "🚫 攔截" if is_blocked else "✅ 通過"
                        f.write(f"[UDP] {time.strftime('%Y-%m-%d %H:%M:%S')} | "
                                f"#{packet_num:,} packets | "
                                f"From {client_ip} | "
                                f"Size: {len(data)} bytes | "
                                f"{status}\n")
                except Exception as log_error:
                    pass
                
        except Exception as e:
            # 靜默忽略錯誤，不打印以避免輸出過多
            pass

# UDP 伺服器
class ThreadedUDPServer(UDPServer, ThreadingMixIn):
    """支持多線程的 UDP 伺服器"""
    daemon_threads = True
    allow_reuse_address = True

# 防禦狀態
class DefenseSystem:
    def __init__(self):
        self.ip_requests = defaultdict(lambda: deque())  # IP請求記錄
        self.ip_blocked = {}  # IP黑名單 {ip: until_time}
        self.connection_count = defaultdict(int)  # 當前連接數
        self.ip_info = defaultdict(lambda: {
            'first_seen': time.time(),
            'total_requests': 0,
            'blocked_requests': 0,
            'user_agents': set(),
            'paths': defaultdict(int)
        })
        self.lock = threading.Lock()
        
    def check_rate_limit(self, ip, max_requests=20, time_window=10):
        """速率限制: 10秒內最多20個請求"""
        if not defense_config['rate_limiting']:
            return True
            
        with self.lock:
            now = time.time()
            self.ip_requests[ip].append(now)
            
            # 清理舊記錄
            while self.ip_requests[ip] and self.ip_requests[ip][0] < now - time_window:
                self.ip_requests[ip].popleft()
            
            # 檢查是否超過限制
            if len(self.ip_requests[ip]) > max_requests:
                # 加入黑名單30秒
                self.ip_blocked[ip] = now + 30
                return False
            
            return True
    
    def is_ip_blocked(self, ip):
        """檢查 IP 是否在黑名單"""
        if not defense_config['ip_blacklist']:
            return False
            
        with self.lock:
            if ip in self.ip_blocked:
                if time.time() < self.ip_blocked[ip]:
                    return True
                else:
                    del self.ip_blocked[ip]
            return False
    
    def check_connection_limit(self, ip, max_connections=10):
        """連接數限制: 每個IP最多10個並發連接"""
        if not defense_config['connection_limit']:
            return True
            
        with self.lock:
            return self.connection_count[ip] < max_connections
    
    def increment_connection(self, ip):
        with self.lock:
            self.connection_count[ip] += 1
    
    def decrement_connection(self, ip):
        with self.lock:
            if self.connection_count[ip] > 0:
                self.connection_count[ip] -= 1
    
    def validate_request(self, headers):
        """請求驗證: 檢查必要的 headers"""
        if not defense_config['request_validation']:
            return True
            
        # 檢查 User-Agent
        user_agent = headers.get('User-Agent', '')
        if not user_agent or len(user_agent) < 5:
            return False
        
        return True
    
    def calculate_adaptive_delay(self):
        global request_count, blocked_count
        """自適應延遲: 根據當前負載動態調整"""
        if not defense_config['adaptive_delay']:
            return 0
            
        elapsed = time.time() - start_time
        rps = (request_count-blocked_count) / elapsed if elapsed > 0 else 0
        
        if rps > 200:
            return 1.0  # 高負載: 1秒延遲
        elif rps > 100:
            return 0.5  # 中等負載: 0.5秒
        elif rps > 50:
            return 0.2  # 輕度負載: 0.2秒
        return 0
    
    def log_request(self, ip, path, user_agent):
        """記錄請求詳細信息"""
        with self.lock:
            self.ip_info[ip]['total_requests'] += 1
            self.ip_info[ip]['user_agents'].add(user_agent[:50])
            self.ip_info[ip]['paths'][path] += 1
    
    def log_block(self, ip, reason, details):
        """記錄攔截事件"""
        global block_logs, block_reasons
        with self.lock:
            self.ip_info[ip]['blocked_requests'] += 1
            block_reasons[reason] += 1
            
            log_entry = {
                'time': time.strftime('%H:%M:%S'),
                'ip': ip,
                'reason': reason,
                'details': details,
                'total_from_ip': self.ip_info[ip]['total_requests']
            }
            block_logs.append(log_entry)
    
    def get_ip_analysis(self, ip):
        """獲取IP的詳細分析"""
        with self.lock:
            if ip not in self.ip_info:
                return None
            
            info = self.ip_info[ip]
            duration = time.time() - info['first_seen']
            
            return {
                'duration': duration,
                'total_requests': info['total_requests'],
                'blocked_requests': info['blocked_requests'],
                'request_rate': info['total_requests'] / duration if duration > 0 else 0,
                'user_agents': list(info['user_agents']),
                'top_paths': sorted(info['paths'].items(), key=lambda x: x[1], reverse=True)[:5],
                'threat_level': self._calculate_threat_level(ip)
            }
    
    def _calculate_threat_level(self, ip):
        """計算威脅等級"""
        info = self.ip_info[ip]
        duration = time.time() - info['first_seen']
        rate = info['total_requests'] / duration if duration > 0 else 0
        block_rate = info['blocked_requests'] / info['total_requests'] if info['total_requests'] > 0 else 0
        
        if block_rate > 0.5 or rate > 50:
            return "🔴 高危"
        elif block_rate > 0.3 or rate > 20:
            return "🟠 中危"
        elif block_rate > 0.1 or rate > 10:
            return "🟡 低危"
        else:
            return "🟢 正常"
    
    def get_stats(self):
        """獲取防禦統計"""
        with self.lock:
            return {
                'blocked_ips': len(self.ip_blocked),
                'total_connections': sum(self.connection_count.values()),
                'monitored_ips': len(self.ip_requests),
                'unique_attackers': sum(1 for info in self.ip_info.values() if info['blocked_requests'] > 0)
            }
    
    def get_recent_blocks(self, limit=10):
        """獲取最近的攔截記錄"""
        return list(block_logs)[-limit:]
    
    def clear_blacklist(self):
        """清除所有黑名單"""
        with self.lock:
            cleared_count = len(self.ip_blocked)
            self.ip_blocked.clear()
            return cleared_count
    
    def check_request(self, ip, protocol='HTTP', path='/', headers=None):
        """
        統一的防禦檢查方法
        返回 (should_block, reason) - should_block 為 True 時表示應該攔截
        """
        if headers is None:
            headers = {}
        
        # 1. 檢查 IP 黑名單
        if self.is_ip_blocked(ip):
            return True, "IP 黑名單"
        
        # 2. 檢查速率限制
        # UDP 洪泛攻擊防禦：更嚴格的限制
        if protocol == 'UDP':
            # UDP 限制更嚴格：10秒內最多 100 個包（正常客戶端不會發這麼多）
            max_requests = 100
            time_window = 10
        else:
            # HTTP 請求：10秒內最多 20 個請求
            max_requests = 20
            time_window = 10
        
        # 先檢查是否超限
        with self.lock:
            now = time.time()
            self.ip_requests[ip].append(now)
            
            # 清理舊記錄
            while self.ip_requests[ip] and self.ip_requests[ip][0] < now - time_window:
                self.ip_requests[ip].popleft()
            
            request_count_for_ip = len(self.ip_requests[ip])
        
        if request_count_for_ip > max_requests:
            # 加入黑名單 30 秒
            with self.lock:
                self.ip_blocked[ip] = now + 30
            
            # 調試日誌：記錄攔截事件
            try:
                with open('server_log.txt', 'a', encoding='utf-8') as f:
                    f.write(f"[防禦] UDP 速率限制觸發: {ip} 在 10 秒內有 {request_count_for_ip} 個包\n")
            except:
                pass
            
            return True, "速率限制"
        
        # 3. 檢查連接限制
        if protocol == 'HTTP' and not self.check_connection_limit(ip):
            return True, "連接數限制"
        
        # 4. 請求驗證（HTTP 專用）
        if protocol == 'HTTP' and not self.validate_request(headers):
            return True, "請求驗證失敗"
        
        # 記錄請求
        self.log_request(ip, path, headers.get('User-Agent', 'Unknown'))
        
        return False, "正常"
    
    def unblock_ip(self, ip):
        """解除特定IP的封鎖"""
        with self.lock:
            if ip in self.ip_blocked:
                del self.ip_blocked[ip]
                return True
            return False

defense_system = DefenseSystem()

class DefenseHandler(BaseHTTPRequestHandler):
    def handle(self):
        """覆寫 handle 方法以捕捉所有連接錯誤"""
        try:
            super().handle()
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError, OSError):
            # 連接已中斷,安靜地忽略
            pass
    
    def do_GET(self):
        global request_count, blocked_count
        
        client_ip = self.client_address[0]
        request_method = self.command
        request_path = self.path
        user_agent = self.headers.get('User-Agent', 'Unknown')
        
        start_request_time = time.time()
        
        # 如果是 POST/PUT 請求,先讀取請求體避免 TCP 緩衝區殘留
        if request_method in ['POST', 'PUT', 'PATCH']:
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    # 快速讀取並丟棄請求體,避免阻塞
                    self.rfile.read(content_length)
            except (ValueError, OSError, ConnectionAbortedError, BrokenPipeError):
                pass
        
        # 監控儀表板 - 實時監控頁面
        if request_path == '/monitor':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            # 獲取當前系統資源狀況
            system_stats = server_monitor.get_current_stats()
            uptime = time.time() - start_time
            request_rate = get_recent_request_rate()
            
            # 計算平均延遲
            recent_delays = []
            with requests_log_lock:
                for req in list(recent_requests)[-20:]:  # 最近20個請求
                    if 'delay' in req:
                        recent_delays.append(req['delay'])
            avg_delay = (sum(recent_delays) / len(recent_delays) / 1000) if recent_delays else 0  # 轉換為秒
            
            # 準備模板數據
            monitor_data = {
                'request_rate': request_rate,
                'avg_delay': avg_delay,
                'request_count': request_count,
                'blocked_count': blocked_count,
                'cpu_percent': system_stats['cpu_percent'],
                'memory_percent': system_stats['memory_percent'],
                'network_sent_rate': system_stats['network_sent_rate'],
                'network_recv_rate': system_stats['network_recv_rate'],
                'uptime': uptime
            }
            
            # 使用模板渲染
            monitor_html = template_renderer.render_monitor_dashboard(monitor_data)
            self.wfile.write(monitor_html.encode('utf-8'))
            return
        
        # 管理功能 - 清除黑名單
        if request_path == '/admin/clear-blacklist':
            cleared = defense_system.clear_blacklist()
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(f"""
            <html>
            <head>
                <meta http-equiv="refresh" content="2;url=/">
                <style>
                    body {{
                        font-family: Arial;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        color: white;
                    }}
                    .message {{
                        background: rgba(0,0,0,0.3);
                        padding: 40px;
                        border-radius: 20px;
                        text-align: center;
                    }}
                </style>
            </head>
            <body>
                <div class="message">
                    <h1>✅ 黑名單已清除</h1>
                    <p>已解除 {cleared} 個 IP 的封鎖</p>
                    <p>2秒後自動返回...</p>
                </div>
            </body>
            </html>
            """.encode('utf-8'))
            return
        
        # 記錄請求信息
        defense_system.log_request(client_ip, request_path, user_agent)
        
        # 立即增加全局請求計數（在防禦檢查之前，因為這是收到的所有請求）
        with request_lock:
            request_count += 1
        
        try:
            # 1. 檢查 IP 黑名單
            if defense_system.is_ip_blocked(client_ip):
                defense_system.log_block(client_ip, "IP黑名單", f"已被封鎖,嘗試訪問 {request_path}")
                try:
                    self.send_error(403, "IP Blocked - You are in blacklist")
                except (ConnectionAbortedError, BrokenPipeError):
                    pass
                with request_lock:
                    blocked_count += 1
                return
            
            # 2. 檢查連接數限制
            if not defense_system.check_connection_limit(client_ip):
                conn_count = defense_system.connection_count[client_ip]
                defense_system.log_block(client_ip, "連接數限制", f"並發連接: {conn_count}, UA: {user_agent[:30]}")
                try:
                    self.send_error(429, "Too Many Connections")
                except (ConnectionAbortedError, BrokenPipeError):
                    pass
                with request_lock:
                    blocked_count += 1
                return
            
            defense_system.increment_connection(client_ip)
            
            # 3. 速率限制檢查
            if not defense_system.check_rate_limit(client_ip):
                rate = len(defense_system.ip_requests[client_ip])
                defense_system.log_block(client_ip, "速率限制", f"10秒內 {rate} 個請求, 路徑: {request_path}")
                try:
                    self.send_error(429, "Rate Limit Exceeded")
                except (ConnectionAbortedError, BrokenPipeError):
                    pass
                with request_lock:
                    blocked_count += 1
                return
            
            # 4. 請求驗證
            if not defense_system.validate_request(self.headers):
                defense_system.log_block(client_ip, "請求驗證失敗", f"缺少或無效 User-Agent, 路徑: {request_path}")
                try:
                    self.send_error(400, "Invalid Request - Missing or invalid headers")
                except (ConnectionAbortedError, BrokenPipeError):
                    pass
                with request_lock:
                    blocked_count += 1
                return
            
            # 5. 自適應延遲
            delay = defense_system.calculate_adaptive_delay()
            if delay > 0:
                time.sleep(delay)
            
            # 記錄允許通過的請求時間戳（用於計算允許通過的請求速率）
            with allowed_timestamps_lock:
                allowed_timestamps.append(time.time())

            
            # 收集 HTTP 標頭
            headers_dict = dict(self.headers.items())
            
            # 分析封包要求
            base_operations, features = server_monitor.analyze_packet_requirements(
                request_method, request_path, headers_dict
            )
            
            # 更新封包統計
            server_monitor.update_packet_stats(request_method, request_path, headers_dict)
            server_monitor.record_unique_headers(headers_dict)
            
            # 獲取系統狀態
            current_stats = server_monitor.get_system_stats()
            elapsed = time.time() - start_time
            rps = get_recent_request_rate()
            
            # 狀態判定
            if rps > 200:
                status = "🔴 嚴重過載"
                status_color = "#ff0000"
            elif rps > 100:
                status = "🟠 過載中"
                status_color = "#ff8800"
            elif rps > 50:
                status = "🟡 負載偏高"
                status_color = "#ffcc00"
            else:
                status = "🟢 正常運作"
                status_color = "#00ff00"
            
            # 防禦統計
            defense_stats = defense_system.get_stats()
            
            # 獲取最近攔截記錄
            recent_blocks = defense_system.get_recent_blocks(10)
            
            # 獲取當前IP分析
            ip_analysis = defense_system.get_ip_analysis(client_ip)
            
            # 攔截原因統計
            top_block_reasons = sorted(block_reasons.items(), key=lambda x: x[1], reverse=True)[:5]
            
            # 防禦機制列表
            defense_mechanisms = []
            for key, enabled in defense_config.items():
                status_badge = "✅" if enabled else "❌"
                mechanism_names = {
                    'rate_limiting': f"{status_badge} 速率限制 (20 req/10s)",
                    'ip_blacklist': f"{status_badge} IP 黑名單 (30秒封鎖)",
                    'connection_limit': f"{status_badge} 連接數限制 (10 concurrent)",
                    'challenge_response': f"{status_badge} 挑戰-響應驗證",
                    'request_validation': f"{status_badge} 請求驗證 (Headers)",
                    'adaptive_delay': f"{status_badge} 自適應延遲 (動態)"
                }
                defense_mechanisms.append({
                    'name': mechanism_names.get(key, key),
                    'enabled': enabled
                })
            
            # 生成黑名單 IP 列表
            blacklist_ips = []
            for ip, until_time in defense_system.ip_blocked.items():
                remaining = int(until_time - time.time())
                if remaining > 0:
                    blacklist_ips.append(f"{ip} (剩餘 {remaining}秒)")
            
            # 生成攔截日誌
            blocked_logs = []
            for log in reversed(recent_blocks):
                if 'time' in log:  # 確保 log 有 'time' 鍵
                    blocked_logs.append(
                        f"[{log['time']}] {log['reason']} - IP: {log['ip']} | {log['details']}"
                    )
            
            # 計算處理時間
            process_delay = int((time.time() - start_request_time) * 1000)
            
            # 構建日誌條目
            log_entry = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'request_id': request_count,
                'client_ip': client_ip,
                'method': request_method,
                'path': request_path,
                'headers': headers_dict,
                'actions': base_operations,
                'packet_features': features,
                'cpu_percent': current_stats['cpu_percent'],
                'memory_percent': current_stats['memory_percent'],
                'network_sent_rate': server_monitor.format_bytes(current_stats['network_sent_rate']) + '/s',
                'network_recv_rate': server_monitor.format_bytes(current_stats['network_recv_rate']) + '/s',
                'delay': process_delay,
                'status': status,
                'requests_per_sec': rps,
            }
            
            # 先添加當前請求到記錄中
            with requests_log_lock:
                recent_requests.append(log_entry)
            
            # 生成允許日誌 (最近成功的請求,包含當前這個)
            allowed_logs = []
            with requests_log_lock:
                for log in list(recent_requests)[-10:]:
                    allowed_logs.append(
                        f"#{log.get('request_id', '?')} | {log.get('timestamp', '?')} | {log.get('client_ip', '?')} | {log.get('method', '?')} {log.get('path', '?')}"
                    )
            
            # 準備模板數據
            template_data = {
                'status': status,
                'status_color': status_color,
                'total_requests': request_count,
                'allowed_requests': request_count - blocked_count,
                'blocked_requests': blocked_count,
                'requests_per_sec': rps,
                'cpu_percent': current_stats['cpu_percent'],
                'memory_percent': current_stats['memory_percent'],
                'network_sent_rate': current_stats['network_sent_rate'],
                'network_recv_rate': current_stats['network_recv_rate'],
                'delay': process_delay,
                'uptime': elapsed,
                'defense_mechanisms': defense_mechanisms,
                'blacklist_ips': blacklist_ips,
                'blacklist_count': len(defense_system.ip_blocked),
                'blocked_logs': blocked_logs,
                'allowed_logs': allowed_logs,
                'client_ip': client_ip,
                'method': request_method,
                'path': request_path,
                'timestamp': log_entry['timestamp'],
                'packet_features': features,
                'headers': headers_dict,
                'actions': base_operations,
                'defense_stats': defense_stats,
                'ip_analysis': ip_analysis,
                'block_reasons': top_block_reasons,
                'block_rate': (blocked_count/request_count*100 if request_count > 0 else 0)
            }
            
            # 使用模板渲染響應
            response = template_renderer.render_defense_dashboard(template_data)
            
            # 回應請求
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            try:
                self.wfile.write(response.encode('utf-8'))
            except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
                pass
                
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            # 連接已中斷,忽略錯誤
            pass
        finally:
            # 減少連接計數
            defense_system.decrement_connection(client_ip)
    
    def do_POST(self):
        try:
            self.do_GET()
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            pass
    
    def log_message(self, format, *args):
        # 每100個請求輸出一次
        # if request_count % 100 == 0:
            # print(f"[{time.strftime('%H:%M:%S')}] 請求: {request_count} | 攔截: {blocked_count}")
        # 其他時間不輸出,避免大量日誌
        pass

class SilentHTTPServer(ThreadingHTTPServer):
    """自定義 HTTPServer,忽略連接錯誤"""
    def handle_error(self, request, client_address):
        """覆寫錯誤處理,忽略連接相關錯誤"""
        import sys
        exc_type, exc_value = sys.exc_info()[:2]
        
        # 忽略連接錯誤
        if isinstance(exc_value, (ConnectionAbortedError, BrokenPipeError, 
                                  ConnectionResetError, OSError)):
            return
        
        # 其他錯誤才顯示
        super().handle_error(request, client_address)

def run_server(port=8001):
    # 使用全局防禦系統實例
    global defense_system
    global request_count, blocked_count
    global start_time
    # 啟動所有監控線程 (系統資源監控 + 性能記錄)
    
    server_monitor.start_monitoring(get_request_count, start_time)
    
    # 監聽所有接口,允許從不同IP訪問
    server_address = ('0.0.0.0', port)
    httpd = SilentHTTPServer(server_address, DefenseHandler)
    
    # UDP 監聽在相同端口（TCP 和 UDP 可以使用相同端口）
    udp_port = port
    
    print("="*60)
    print("[防禦] DDoS 防禦測試伺服器")
    print("="*60)
    print(f"伺服器啟動於:")
    print(f"  - TCP (HTTP) 端口: {port}")
    print(f"  - UDP 端口: {udp_port} (UDP Flood 防禦)")
    print(f"  - 本地 HTTP: http://127.0.0.1:{port}")
    print(f"  - 局域網 HTTP: http://0.0.0.0:{port}")
    print("\n啟用的防禦機制:")
    for defense, enabled in defense_config.items():
        status = "✅" if enabled else "❌"
        print(f"  {defense}")
    print("\n[監控] 性能監控已啟動")
    print("按 Ctrl+C 停止伺服器")
    print("="*60 + "\n")
    
    # 初始化日誌文件
    try:
        import os
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server_log.txt')
        with open(log_path, 'w', encoding='utf-8') as f:
            from datetime import datetime
            f.write(f"{'='*80}\n")
            f.write(f"DDoS 防禦伺服器日誌 (TCP + UDP 防禦)\n")
            f.write(f"啟動時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"TCP 端口: {port}\n")
            f.write(f"UDP 端口: {udp_port}\n")
            f.write(f"日誌位置: {log_path}\n")
            f.write(f"{'='*80}\n")
    except Exception as e:
        pass
    
    # 在單獨的線程中啟動 UDP 伺服器並應用防禦
    udp_server = None
    try:
        # 設置防禦系統到 UDP 處理器
        print(f"[調試] 防禦系統物件: {defense_system}")
        print(f"[調試] 設置防禦系統到 UDP 處理器...")
        UDPFloodHandler.defense_system = defense_system
        print(f"[調試] UDP 處理器防禦系統: {UDPFloodHandler.defense_system}")
        
        udp_server = ThreadedUDPServer(('0.0.0.0', udp_port), UDPFloodHandler)
        udp_thread = threading.Thread(target=udp_server.serve_forever, daemon=True)
        udp_thread.start()
        print(f"[系統] UDP 監聽線程已啟動 (端口 {udp_port})\n")
    except Exception as e:
        print(f"[警告] 無法啟動 UDP 伺服器: {e}\n")
        import traceback
        traceback.print_exc()
    
    # 啟動實時統計輸出線程
    def stats_printer():
        """每 2 秒輸出一次統計信息"""
        while True:
            time.sleep(2)
            try:
                with request_lock:
                    req = request_count
                    blk = blocked_count
                    passed = req - blk
                print(f"[統計] 總請求: {req:>8} | 允許通過: {passed:>8} | 攔截: {blk:>8} | "
                      f"攔截率: {(blk/req*100 if req > 0 else 0):>5.1f}%")
            except:
                pass
    
    stats_thread = threading.Thread(target=stats_printer, daemon=True)
    stats_thread.start()
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n[停止] 正在停止伺服器...")
        if udp_server:
            udp_server.shutdown()
        passed = request_count - blocked_count
        print(f"  總請求數: {request_count}")
        print(f"  允許通過: {passed}")
        print(f"  攔截數: {blocked_count}")
        print(f"  攔截率: {(blocked_count/request_count*100 if request_count > 0 else 0):.1f}%")
        print("\n[報告] 正在生成最終報告...")
        
        # 收集被攔截的所有 IP (從 block_logs 中統計)
        blocked_ips = {}
        for log in block_logs:
            ip = log['ip']
            if ip not in blocked_ips:
                blocked_ips[ip] = 0
            blocked_ips[ip] += 1
        
        # 傳遞攔截統計資料到報告生成函數
        server_monitor.generate_final_report(
            request_count, 
            start_time, 
            blocked_count, 
            dict(block_reasons),
            blocked_ips
        )
        print("[完成] 報告已保存到 performance_report.txt")
        httpd.shutdown()

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--no-defense':
        print("[警告] 警告: 關閉所有防禦機制!")
        for key in defense_config:
            defense_config[key] = False
    
    run_server(port=8001)  # 防禦伺服器使用 8001 端口
