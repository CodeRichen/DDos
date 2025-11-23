"""
進階防禦伺服器 - 包含多種 DDoS 防禦機制
僅用於教育目的和本地測試
"""
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import ThreadingMixIn
import time
import threading
from collections import defaultdict, deque
import hashlib
import json

# 全局統計
request_count = 0
blocked_count = 0
start_time = time.time()
request_lock = threading.Lock()

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

# 防禦狀態
class DefenseSystem:
    def __init__(self):
        self.ip_requests = defaultdict(lambda: deque(maxlen=100))  # IP請求記錄
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
        """自適應延遲: 根據當前負載動態調整"""
        if not defense_config['adaptive_delay']:
            return 0
            
        elapsed = time.time() - start_time
        rps = request_count / elapsed if elapsed > 0 else 0
        
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
        request_path = self.path
        user_agent = self.headers.get('User-Agent', 'Unknown')
        
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
            
            # 更新統計
            with request_lock:
                request_count += 1
                current_count = request_count
                current_blocked = blocked_count
            
            # 計算實時數據
            elapsed = time.time() - start_time
            rps = current_count / elapsed if elapsed > 0 else 0
            
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
            
            defense_stats = defense_system.get_stats()
            
            # 防禦狀態顯示
            active_defenses = [k for k, v in defense_config.items() if v]
            defense_status = "🛡️ 啟用" if active_defenses else "❌ 關閉"
            
            # 獲取最近攔截記錄
            recent_blocks = defense_system.get_recent_blocks(5)
            
            # 獲取當前IP分析
            ip_analysis = defense_system.get_ip_analysis(client_ip)
            
            # 攔截原因統計
            top_block_reasons = sorted(block_reasons.items(), key=lambda x: x[1], reverse=True)[:5]
            
            # 回應請求
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            response = f"""
            <html>
            <head>
                <title>DDoS 防禦測試伺服器</title>
                <meta http-equiv="refresh" content="1">
                <style>
                    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                    body {{
                        font-family: 'Segoe UI', Arial, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        color: white;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        padding: 20px;
                    }}
                    .container {{
                        background: rgba(255, 255, 255, 0.1);
                        backdrop-filter: blur(10px);
                        padding: 30px;
                        border-radius: 20px;
                        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                        max-width: 900px;
                        width: 100%;
                    }}
                    h1 {{
                        text-align: center;
                        font-size: 2em;
                        margin-bottom: 20px;
                        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                    }}
                    .status-box {{
                        background: rgba(0, 0, 0, 0.3);
                        padding: 20px;
                        border-radius: 15px;
                        margin-bottom: 20px;
                        text-align: center;
                    }}
                    .status {{
                        font-size: 1.8em;
                        font-weight: bold;
                        color: {status_color};
                        margin-bottom: 10px;
                    }}
                    .defense-status {{
                        font-size: 1.2em;
                        color: #4CAF50;
                        margin-top: 10px;
                    }}
                    .stats-grid {{
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 15px;
                        margin: 20px 0;
                    }}
                    .stat-card {{
                        background: rgba(0, 0, 0, 0.2);
                        padding: 20px;
                        border-radius: 10px;
                        text-align: center;
                    }}
                    .stat-value {{
                        font-size: 2em;
                        font-weight: bold;
                        color: #fff;
                        margin-bottom: 5px;
                    }}
                    .stat-label {{
                        font-size: 0.9em;
                        color: #ddd;
                    }}
                    .defense-list {{
                        background: rgba(0, 0, 0, 0.2);
                        padding: 20px;
                        border-radius: 10px;
                        margin-top: 20px;
                    }}
                    .defense-item {{
                        display: flex;
                        justify-content: space-between;
                        padding: 10px 0;
                        border-bottom: 1px solid rgba(255,255,255,0.1);
                    }}
                    .defense-item:last-child {{
                        border-bottom: none;
                    }}
                    .spinner {{
                        border: 6px solid rgba(255, 255, 255, 0.3);
                        border-top: 6px solid white;
                        border-radius: 50%;
                        width: 50px;
                        height: 50px;
                        animation: spin 1s linear infinite;
                        margin: 15px auto;
                        display: {('block' if delay > 0 else 'none')};
                    }}
                    @keyframes spin {{
                        0% {{ transform: rotate(0deg); }}
                        100% {{ transform: rotate(360deg); }}
                    }}
                    .progress-bar {{
                        width: 100%;
                        height: 10px;
                        background: rgba(255, 255, 255, 0.2);
                        border-radius: 5px;
                        overflow: hidden;
                        margin: 15px 0;
                    }}
                    .progress-fill {{
                        height: 100%;
                        background: {status_color};
                        width: {min(rps/2, 100)}%;
                        transition: width 0.3s;
                        animation: pulse 1.5s infinite;
                    }}
                    @keyframes pulse {{
                        0%, 100% {{ opacity: 1; }}
                        50% {{ opacity: 0.6; }}
                    }}
                    .badge {{
                        display: inline-block;
                        padding: 5px 10px;
                        border-radius: 5px;
                        font-size: 0.85em;
                        font-weight: bold;
                    }}
                    .badge-on {{ background: #4CAF50; }}
                    .badge-off {{ background: #f44336; }}
                    .log-section {{
                        background: rgba(0, 0, 0, 0.2);
                        padding: 15px;
                        border-radius: 10px;
                        margin-top: 20px;
                        max-height: 300px;
                        overflow-y: auto;
                    }}
                    .log-entry {{
                        background: rgba(255, 0, 0, 0.1);
                        padding: 10px;
                        margin: 5px 0;
                        border-radius: 5px;
                        border-left: 3px solid #ff4444;
                        font-size: 0.85em;
                    }}
                    .log-time {{
                        color: #aaa;
                        font-weight: bold;
                    }}
                    .log-reason {{
                        color: #ff8888;
                        font-weight: bold;
                    }}
                    .ip-analysis {{
                        background: rgba(0, 0, 0, 0.2);
                        padding: 15px;
                        border-radius: 10px;
                        margin-top: 15px;
                    }}
                    .analysis-item {{
                        display: flex;
                        justify-content: space-between;
                        padding: 8px 0;
                        border-bottom: 1px solid rgba(255,255,255,0.1);
                    }}
                    .threat-badge {{
                        padding: 5px 10px;
                        border-radius: 5px;
                        font-weight: bold;
                        font-size: 0.9em;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🛡️ DDoS 防禦測試伺服器</h1>
                    
                    <div class="status-box">
                        <div class="status">{status}</div>
                        <div class="defense-status">防禦系統: {defense_status}</div>
                        <div class="spinner"></div>
                        <div class="progress-bar">
                            <div class="progress-fill"></div>
                        </div>
                    </div>
                    
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-value">{current_count}</div>
                            <div class="stat-label">✅ 成功請求</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{current_blocked}</div>
                            <div class="stat-label">🚫 攔截請求</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{rps:.1f}</div>
                            <div class="stat-label">⚡ 請求/秒</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{delay*1000:.0f}ms</div>
                            <div class="stat-label">⏱️ 當前延遲</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{defense_stats['blocked_ips']}</div>
                            <div class="stat-label">🔒 黑名單IP</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{defense_stats['total_connections']}</div>
                            <div class="stat-label">🔗 當前連接</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{defense_stats['unique_attackers']}</div>
                            <div class="stat-label">⚠️ 攻擊來源</div>
                        </div>
                    </div>
                    
                    <div class="ip-analysis">
                        <h3 style="margin-bottom: 10px;">📍 您的連接分析 ({client_ip})</h3>
                        {f'''
                        <div class="analysis-item">
                            <span>威脅等級</span>
                            <span class="threat-badge">{ip_analysis['threat_level']}</span>
                        </div>
                        <div class="analysis-item">
                            <span>總請求數</span>
                            <span>{ip_analysis['total_requests']}</span>
                        </div>
                        <div class="analysis-item">
                            <span>被攔截</span>
                            <span>{ip_analysis['blocked_requests']} 次</span>
                        </div>
                        <div class="analysis-item">
                            <span>請求速率</span>
                            <span>{ip_analysis['request_rate']:.1f} req/s</span>
                        </div>
                        <div class="analysis-item">
                            <span>連接時長</span>
                            <span>{ip_analysis['duration']:.0f} 秒</span>
                        </div>
                        ''' if ip_analysis else '<p style="color: #888;">無數據</p>'}
                    </div>
                    
                    <div class="log-section">
                        <h3 style="margin-bottom: 10px;">🚫 最近攔截記錄</h3>
                        {(''.join([f'''
                        <div class="log-entry">
                            <span class="log-time">[{log['time']}]</span>
                            <span class="log-reason">{log['reason']}</span>
                            <br>
                            <small>IP: {log['ip']} | {log['details']}</small>
                        </div>
                        ''' for log in reversed(recent_blocks)])) if recent_blocks else '<p style="color: #888; text-align: center;">暫無攔截記錄</p>'}
                    </div>
                    
                    <div class="log-section" style="max-height: 150px;">
                        <h3 style="margin-bottom: 10px;">📊 攔截原因統計</h3>
                        {(''.join([f'''
                        <div style="display: flex; justify-content: space-between; padding: 5px 0;">
                            <span>{reason}</span>
                            <span style="color: #ff8888; font-weight: bold;">{count} 次</span>
                        </div>
                        ''' for reason, count in top_block_reasons])) if top_block_reasons else '<p style="color: #888; text-align: center;">暫無數據</p>'}
                    </div>
                    
                    <div class="defense-list">
                        <h3 style="margin-bottom: 15px;">🛡️ 防禦機制狀態</h3>
                        <div class="defense-item">
                            <span>📊 速率限制 (20 req/10s)</span>
                            <span class="badge {'badge-on' if defense_config['rate_limiting'] else 'badge-off'}">
                                {'啟用' if defense_config['rate_limiting'] else '關閉'}
                            </span>
                        </div>
                        <div class="defense-item">
                            <span>🚫 IP 黑名單 (30秒封鎖)</span>
                            <span class="badge {'badge-on' if defense_config['ip_blacklist'] else 'badge-off'}">
                                {'啟用' if defense_config['ip_blacklist'] else '關閉'}
                            </span>
                        </div>
                        <div class="defense-item">
                            <span>🔗 連接數限制 (10 concurrent)</span>
                            <span class="badge {'badge-on' if defense_config['connection_limit'] else 'badge-off'}">
                                {'啟用' if defense_config['connection_limit'] else '關閉'}
                            </span>
                        </div>
                        <div class="defense-item">
                            <span>✅ 請求驗證 (Headers)</span>
                            <span class="badge {'badge-on' if defense_config['request_validation'] else 'badge-off'}">
                                {'啟用' if defense_config['request_validation'] else '關閉'}
                            </span>
                        </div>
                        <div class="defense-item">
                            <span>⏱️ 自適應延遲 (動態)</span>
                            <span class="badge {'badge-on' if defense_config['adaptive_delay'] else 'badge-off'}">
                                {'啟用' if defense_config['adaptive_delay'] else '關閉'}
                            </span>
                        </div>
                    </div>
                    
                    <p style="margin-top: 20px; text-align: center; font-size: 0.9em; color: #ddd;">
                        運行時間: {elapsed:.0f}秒 | 攔截率: {(current_blocked/(current_count+current_blocked)*100 if current_count+current_blocked > 0 else 0):.1f}%
                        <br>
                        <a href="/admin/clear-blacklist" style="color: #ffcc00; text-decoration: none; font-weight: bold;">
                            🔓 清除黑名單
                        </a>
                    </p>
                </div>
            </body>
            </html>
            """
            try:
                self.wfile.write(response.encode('utf-8'))
            except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
                # 客戶端已斷開連接
                pass
                
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            # 連接已中斷,忽略錯誤
            pass
        finally:
            defense_system.decrement_connection(client_ip)
    
    def do_POST(self):
        try:
            self.do_GET()
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            pass
    
    def log_message(self, format, *args):
        # 每100個請求輸出一次
        if request_count % 100 == 0:
            print(f"[{time.strftime('%H:%M:%S')}] 請求: {request_count} | 攔截: {blocked_count}")
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
    # 監聽所有接口,允許從不同IP訪問
    server_address = ('0.0.0.0', port)
    httpd = SilentHTTPServer(server_address, DefenseHandler)
    
    print("="*60)
    print("🛡️  DDoS 防禦測試伺服器")
    print("="*60)
    print(f"伺服器啟動於:")
    print(f"  - 端口: {port}")
    print(f"  - 本地: http://127.0.0.1:{port}")
    print(f"  - 局域網: http://0.0.0.0:{port}")
    print("\n啟用的防禦機制:")
    for defense, enabled in defense_config.items():
        status = "✅" if enabled else "❌"
        print(f"  {status} {defense}")
    print("\n按 Ctrl+C 停止伺服器")
    print("="*60 + "\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n伺服器已停止")
        print(f"總請求數: {request_count}")
        print(f"攔截數: {blocked_count}")
        httpd.shutdown()

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--no-defense':
        print("⚠️  警告: 關閉所有防禦機制!")
        for key in defense_config:
            defense_config[key] = False
    
    run_server(port=8001)  # 防禦伺服器使用 8001 端口
