"""
簡單的HTTP伺服器用於DDoS測試
僅用於教育目的和本地測試
"""
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import ThreadingMixIn
import time
import threading
from collections import deque
import json
from datetime import datetime
import os

# 導入監控模組和模板渲染模組
import server_monitor
import template_renderer

request_count = 0
request_lock = threading.Lock()
start_time = time.time()

# 最近的請求日誌 (保留最近 50 條)
recent_requests = deque(maxlen=50)
requests_log_lock = threading.Lock()

def get_request_count():
    """獲取當前請求總數"""
    with request_lock:
        return request_count

def log_request_to_file(log_entry):
    """將請求日誌寫入文件 (只記錄不同的標頭組合)"""
    try:
        import os
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server_log.txt')
        
        # 檢查是否是獨特的標頭組合 (簡化版本 - 每種組合只記錄一次)
        header_signature = tuple(sorted(log_entry['headers'].keys()))
        
        # 使用全局變數追蹤已記錄的標頭組合
        if not hasattr(log_request_to_file, 'logged_signatures'):
            log_request_to_file.logged_signatures = set()
        
        # 如果這個標頭組合已經記錄過,且不是特殊請求,則跳過
        if header_signature in log_request_to_file.logged_signatures and log_entry.get('request_id', 0) % 100 != 0:
            return
        
        log_request_to_file.logged_signatures.add(header_signature)
        
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*100}\n")
            f.write(f"時間: {log_entry['timestamp']}\n")
            f.write(f"請求編號: #{log_entry['request_id']}\n")
            f.write(f"來源 IP: {log_entry['client_ip']}\n")
            f.write(f"請求方法: {log_entry['method']}\n")
            f.write(f"請求路徑: {log_entry['path']}\n")
            
            # 封包特徵分析
            if 'packet_features' in log_entry:
                features = log_entry['packet_features']
                f.write(f"\n[封包特徵分析]\n")
                f.write(f"  請求方法: {features['method']}\n")
                f.write(f"  路徑類型: {features['path_type']}\n")
                f.write(f"  需要解析主體: {'是' if features['requires_parsing'] else '否'}\n")
                f.write(f"  需要處理邏輯: {'是' if features['requires_processing'] else '否'}\n")
                f.write(f"  需要生成響應: {'是' if features['requires_response'] else '否'}\n")
            
            f.write(f"\n[收到的封包標頭] (獨特組合 #{len(log_request_to_file.logged_signatures)})\n")
            for key, value in log_entry['headers'].items():
                f.write(f"  {key}: {value}\n")
            
            f.write(f"\n[伺服器底層操作 - 共 {len(log_entry['actions'])} 步]\n")
            for idx, action in enumerate(log_entry['actions'], 1):
                f.write(f"  {idx:2d}. {action}\n")
            
            f.write(f"\n[系統資源佔用]\n")
            f.write(f"  CPU 使用率: {log_entry['cpu_percent']:.1f}%\n")
            f.write(f"  記憶體使用率: {log_entry['memory_percent']:.1f}%\n")
            f.write(f"  網路發送速率: {log_entry['network_sent_rate']}\n")
            f.write(f"  網路接收速率: {log_entry['network_recv_rate']}\n")
            f.write(f"  處理延遲: {log_entry['delay']}ms\n")
            f.write(f"  當前狀態: {log_entry['status']}\n")
            f.write(f"{'='*100}\n")
    except Exception as e:
        print(f"[日誌寫入錯誤] {e}")

class SimpleHandler(BaseHTTPRequestHandler):
    def handle(self):
        """覆寫 handle 方法以捕捉所有連接錯誤"""
        try:
            super().handle()
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError, OSError):
            # 連接已中斷,安靜地忽略
            pass
    
    def do_GET(self):
        global request_count
        
        # 獲取客戶端信息
        client_ip = self.client_address[0]
        request_method = self.command
        request_path = self.path
        
        # 特殊處理 favicon.ico 請求
        if request_path == '/favicon.ico':
            with request_lock:
                request_count += 1
                current_count = request_count
            
            # 收集標頭
            headers_dict = dict(self.headers.items())
            
            # 分析封包要求的底層操作
            operations, features = server_monitor.analyze_packet_requirements(
                request_method, request_path, headers_dict
            )
            
            # 統計封包類型
            server_monitor.update_packet_stats(request_method, request_path, headers_dict)
            
            # 記錄 favicon 請求到日誌
            log_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'request_id': current_count,
                'client_ip': client_ip,
                'method': request_method,
                'path': request_path,
                'headers': headers_dict,
                'actions': operations,  # 使用分析得到的底層操作列表
                'packet_features': features,
                'cpu_percent': 0,
                'memory_percent': 0,
                'network_sent_rate': '0 B/s',
                'network_recv_rate': '0 B/s',
                'delay': 0,
                'status': 'favicon 請求 🖼️',
                'requests_per_sec': 0,
            }
            log_request_to_file(log_entry)
            
            # 返回 204 No Content,瀏覽器會停止重複請求
            self.send_response(204)
            self.end_headers()
            return
        
        with request_lock:
            request_count += 1
            current_count = request_count
        
        # 收集所有 HTTP 標頭
        headers_dict = {}
        for header, value in self.headers.items():
            headers_dict[header] = value
        
        # 分析封包要求的底層操作
        base_operations, features = server_monitor.analyze_packet_requirements(
            request_method, request_path, headers_dict
        )
        
        # 統計封包類型
        server_monitor.update_packet_stats(request_method, request_path, headers_dict)
        
        # 記錄獨特的標頭組合
        server_monitor.record_unique_headers(headers_dict)
        
        # 計算負載和延遲
        elapsed = time.time() - start_time
        requests_per_sec = current_count / elapsed if elapsed > 0 else 0
        
        # 使用基礎操作列表,並添加應用層特定操作
        actions = base_operations.copy()
        actions.append("\n--- 應用層操作 ---")
        actions.append(f"[應用] 計算當前請求速率: {requests_per_sec:.2f} req/s")
        
        # 根據請求速率模擬伺服器壓力
        if requests_per_sec > 100:
            delay = 0.5  # 高負載時延遲0.5秒
            status = "嚴重過載 🔴"
            status_color = "#ff0000"
            actions.append("[應用] 檢測到高負載 (>100 req/s)")
            actions.append("[應用] 應用 500ms 延遲保護伺服器")
            actions.append("[系統] 伺服器進入過載保護模式")
        elif requests_per_sec > 50:
            delay = 0.3
            status = "過載中 🟠"
            status_color = "#ff8800"
            actions.append("[應用] 檢測到中度負載 (>50 req/s)")
            actions.append("[應用] 應用 300ms 延遲")
        elif requests_per_sec > 20:
            delay = 0.1
            status = "負載偏高 🟡"
            status_color = "#ffcc00"
            actions.append("[應用] 檢測到負載偏高 (>20 req/s)")
            actions.append("[應用] 應用 100ms 延遲")
        else:
            delay = 0
            status = "正常運作 🟢"
            status_color = "#00ff00"
            actions.append("[應用] 負載正常,無需延遲")
        
        actions.append(f"[系統] 執行 sleep({delay}s) 模擬處理時間")
        time.sleep(delay)  # 模擬處理延遲
        
        # 獲取當前系統狀態
        current_stats = server_monitor.get_system_stats()
        
        # 創建日誌條目
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'request_id': current_count,
            'client_ip': client_ip,
            'method': request_method,
            'path': request_path,
            'headers': headers_dict,
            'actions': actions,
            'packet_features': features,  # 封包特徵分析
            'cpu_percent': current_stats['cpu_percent'],
            'memory_percent': current_stats['memory_percent'],
            'network_sent_rate': server_monitor.format_bytes(current_stats['network_sent_rate']) + '/s',
            'network_recv_rate': server_monitor.format_bytes(current_stats['network_recv_rate']) + '/s',
            'delay': int(delay * 1000),
            'status': status,
            'requests_per_sec': requests_per_sec,
        }
        
        # 添加到最近請求列表
        with requests_log_lock:
            recent_requests.append(log_entry)
        
        # 寫入日誌文件
        log_request_to_file(log_entry)
        
        actions.append("發送 HTTP 200 響應")
        
        # 回應請求
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        # 生成最近請求的 HTML 報告
        recent_logs_html = ""
        with requests_log_lock:
            for log in list(recent_requests)[-10:]:  # 顯示最近 10 條
                recent_logs_html += f"""
                <div class="log-entry">
                    <div><strong>#{log['request_id']}</strong> | {log['timestamp']} | {log['client_ip']}</div>
                    <div>{log['method']} {log['path']}</div>
                    <div>CPU: {log['cpu_percent']:.1f}% | 記憶體: {log['memory_percent']:.1f}% | 延遲: {log['delay']}ms</div>
                </div>
                """
        
        # 尋找最近的非 GET 根路徑請求(攻擊請求)來顯示在儀表板
        display_request = None
        with requests_log_lock:
            for log in reversed(list(recent_requests)):
                # 跳過 GET 根路徑請求(儀表板訪問)
                if not (log['method'] == 'GET' and log['path'] == '/'):
                    display_request = log
                    break
        
        # 如果沒有找到攻擊請求,使用當前請求
        if display_request is None:
            display_request = log_entry
        
        # 準備模板數據 - 使用找到的攻擊請求而非當前 GET 請求
        template_data = {
            'status': status,
            'status_color': status_color,
            'total_requests': current_count,
            'requests_per_sec': requests_per_sec,
            'cpu_percent': current_stats['cpu_percent'],
            'memory_percent': current_stats['memory_percent'],
            'network_sent': server_monitor.format_bytes(current_stats['network_sent_rate']) + '/s',
            'network_recv': server_monitor.format_bytes(current_stats['network_recv_rate']) + '/s',
            'delay': int(delay * 1000),
            'uptime': elapsed,
            'client_ip': display_request['client_ip'],
            'method': display_request['method'],
            'path': display_request['path'],
            'timestamp': display_request['timestamp'],
            'packet_features': display_request['packet_features'],
            'headers': display_request['headers'],
            'actions': display_request['actions'],
            'recent_logs_html': recent_logs_html if recent_logs_html else '<div>暫無記錄</div>',
        }
        
        # 使用模板渲染響應
        response = template_renderer.render_dashboard(template_data)
        try:
            self.wfile.write(response.encode('utf-8'))
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            # 客戶端已斷開連接
            pass
    
    def do_POST(self):
        """處理 POST 請求"""
        global request_count
        client_ip = self.client_address[0]
        request_method = self.command
        request_path = self.path
        
        start_time = time.time()
        
        # 線程安全地更新請求計數
        with request_lock:
            request_count += 1
            current_count = request_count
        
        # 讀取 POST 數據
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b''
        
        # 收集所有請求標頭
        headers_dict = dict(self.headers.items())
        
        # 分析封包的底層需求
        actions, features = server_monitor.analyze_packet_requirements(
            request_method, request_path, headers_dict
        )
        
        # 更新統計資訊
        server_monitor.update_packet_stats(request_method, request_path, headers_dict)
        server_monitor.record_unique_headers(headers_dict)
        
        # 獲取當前系統資源統計
        current_stats = server_monitor.get_system_stats()
        delay = time.time() - start_time
        
        # 構建日誌條目
        log_entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'request_id': current_count,
            'client_ip': client_ip,
            'method': request_method,
            'path': request_path,
            'headers': headers_dict,
            'actions': actions,
            'packet_features': features,
            'cpu_percent': current_stats['cpu_percent'],
            'memory_percent': current_stats['memory_percent'],
            'network_sent_rate': server_monitor.format_bytes(current_stats['network_sent_rate']) + '/s',
            'network_recv_rate': server_monitor.format_bytes(current_stats['network_recv_rate']) + '/s',
            'delay': int(delay * 1000),
            'post_data_size': len(post_data),
            'status': '正常運作 🟢',
            'requests_per_sec': 0,
        }
        
        # 添加到最近請求列表
        with requests_log_lock:
            recent_requests.append(log_entry)
        
        # 寫入日誌文件
        log_request_to_file(log_entry)
        
        # 發送響應
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response_data = {
            'status': 'success',
            'request_id': current_count,
            'message': 'POST request received',
            'data_received': len(post_data)
        }
        
        try:
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            # 客戶端已斷開連接
            pass
    
    def do_PUT(self):
        """處理 PUT 請求"""
        global request_count
        client_ip = self.client_address[0]
        request_method = self.command
        request_path = self.path
        start_time = time.time()
        
        with request_lock:
            request_count += 1
            current_count = request_count
        
        content_length = int(self.headers.get('Content-Length', 0))
        put_data = self.rfile.read(content_length) if content_length > 0 else b''
        headers_dict = dict(self.headers.items())
        
        actions, features = server_monitor.analyze_packet_requirements(
            request_method, request_path, headers_dict
        )
        server_monitor.update_packet_stats(request_method, request_path, headers_dict)
        server_monitor.record_unique_headers(headers_dict)
        
        current_stats = server_monitor.get_system_stats()
        delay = time.time() - start_time
        
        log_entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'request_id': current_count,
            'client_ip': client_ip,
            'method': request_method,
            'path': request_path,
            'headers': headers_dict,
            'actions': actions,
            'packet_features': features,
            'cpu_percent': current_stats['cpu_percent'],
            'memory_percent': current_stats['memory_percent'],
            'network_sent_rate': server_monitor.format_bytes(current_stats['network_sent_rate']) + '/s',
            'network_recv_rate': server_monitor.format_bytes(current_stats['network_recv_rate']) + '/s',
            'delay': int(delay * 1000),
            'status': '正常運作 🟢',
            'requests_per_sec': 0,
        }
        
        with requests_log_lock:
            recent_requests.append(log_entry)
        log_request_to_file(log_entry)
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response_data = {'status': 'success', 'request_id': current_count, 'message': 'PUT request received'}
        try:
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            pass
    
    def do_DELETE(self):
        """處理 DELETE 請求"""
        global request_count
        client_ip = self.client_address[0]
        request_method = self.command
        request_path = self.path
        start_time = time.time()
        
        with request_lock:
            request_count += 1
            current_count = request_count
        
        headers_dict = dict(self.headers.items())
        
        actions, features = server_monitor.analyze_packet_requirements(
            request_method, request_path, headers_dict
        )
        server_monitor.update_packet_stats(request_method, request_path, headers_dict)
        server_monitor.record_unique_headers(headers_dict)
        
        current_stats = server_monitor.get_system_stats()
        delay = time.time() - start_time
        
        log_entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'request_id': current_count,
            'client_ip': client_ip,
            'method': request_method,
            'path': request_path,
            'headers': headers_dict,
            'actions': actions,
            'packet_features': features,
            'cpu_percent': current_stats['cpu_percent'],
            'memory_percent': current_stats['memory_percent'],
            'network_sent_rate': server_monitor.format_bytes(current_stats['network_sent_rate']) + '/s',
            'network_recv_rate': server_monitor.format_bytes(current_stats['network_recv_rate']) + '/s',
            'delay': int(delay * 1000),
            'status': '正常運作 🟢',
            'requests_per_sec': 0,
        }
        
        with requests_log_lock:
            recent_requests.append(log_entry)
        log_request_to_file(log_entry)
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response_data = {'status': 'success', 'request_id': current_count, 'message': 'DELETE request received'}
        try:
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            pass
    
    def do_HEAD(self):
        """處理 HEAD 請求"""
        global request_count
        client_ip = self.client_address[0]
        request_method = self.command
        request_path = self.path
        start_time = time.time()
        
        with request_lock:
            request_count += 1
            current_count = request_count
        
        headers_dict = dict(self.headers.items())
        
        actions, features = server_monitor.analyze_packet_requirements(
            request_method, request_path, headers_dict
        )
        server_monitor.update_packet_stats(request_method, request_path, headers_dict)
        server_monitor.record_unique_headers(headers_dict)
        
        current_stats = server_monitor.get_system_stats()
        delay = time.time() - start_time
        
        log_entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'request_id': current_count,
            'client_ip': client_ip,
            'method': request_method,
            'path': request_path,
            'headers': headers_dict,
            'actions': actions,
            'packet_features': features,
            'cpu_percent': current_stats['cpu_percent'],
            'memory_percent': current_stats['memory_percent'],
            'network_sent_rate': server_monitor.format_bytes(current_stats['network_sent_rate']) + '/s',
            'network_recv_rate': server_monitor.format_bytes(current_stats['network_recv_rate']) + '/s',
            'delay': int(delay * 1000),
            'status': '正常運作 🟢',
            'requests_per_sec': 0,
        }
        
        with requests_log_lock:
            recent_requests.append(log_entry)
        log_request_to_file(log_entry)
        
        # HEAD 請求只返回標頭,不返回內容
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', '0')
        self.end_headers()
    
    def do_OPTIONS(self):
        """處理 OPTIONS 請求"""
        global request_count
        client_ip = self.client_address[0]
        request_method = self.command
        request_path = self.path
        start_time = time.time()
        
        with request_lock:
            request_count += 1
            current_count = request_count
        
        headers_dict = dict(self.headers.items())
        
        actions, features = server_monitor.analyze_packet_requirements(
            request_method, request_path, headers_dict
        )
        server_monitor.update_packet_stats(request_method, request_path, headers_dict)
        server_monitor.record_unique_headers(headers_dict)
        
        current_stats = server_monitor.get_system_stats()
        delay = time.time() - start_time
        
        log_entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'request_id': current_count,
            'client_ip': client_ip,
            'method': request_method,
            'path': request_path,
            'headers': headers_dict,
            'actions': actions,
            'packet_features': features,
            'cpu_percent': current_stats['cpu_percent'],
            'memory_percent': current_stats['memory_percent'],
            'network_sent_rate': server_monitor.format_bytes(current_stats['network_sent_rate']) + '/s',
            'network_recv_rate': server_monitor.format_bytes(current_stats['network_recv_rate']) + '/s',
            'delay': int(delay * 1000),
            'status': '正常運作 🟢',
            'requests_per_sec': 0,
        }
        
        with requests_log_lock:
            recent_requests.append(log_entry)
        log_request_to_file(log_entry)
        
        # OPTIONS 請求返回允許的方法
        self.send_response(200)
        self.send_header('Allow', 'GET, POST, PUT, DELETE, HEAD, OPTIONS')
        self.send_header('Content-Length', '0')
        self.end_headers()
    
    def log_message(self, format, *args):
        # 完全禁用終端日誌輸出,所有資訊記錄到文件
        pass

class SilentHTTPServer(ThreadingHTTPServer):
    """自定義 ThreadingHTTPServer,支持多線程並忽略連接錯誤"""
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

def run_server(port=8000):
    server_address = ('0.0.0.0', port)
    httpd = SilentHTTPServer(server_address, SimpleHandler)
    
    # 配置線程參數以提高並發處理能力
    httpd.daemon_threads = True  # 守護線程,主程序結束時自動結束
    httpd.request_queue_size = 100  # 增加請求隊列大小
    
    # 啟動監控線程
    server_monitor.start_monitoring(get_request_count, start_time)
    
    print("="*60)
    print("⚠️  無防禦測試伺服器 (多線程版 + 詳細報告)")
    print("="*60)
    print(f"伺服器啟動於:")
    print(f"  - 端口: {port}")
    print(f"  - 本地: http://127.0.0.1:{port}")
    print(f"  - 局域網: http://0.0.0.0:{port}")
    print(f"  - 防禦: ❌ 無任何防禦機制")
    print(f"  - 並發: ✅ 支持多線程處理")
    print(f"  - 隊列: {httpd.request_queue_size} 個請求")
    print(f"  - 報告: ✅ 網頁顯示 + 文件記錄 (server_log.txt)")
    print(f"  - 監控: ✅ CPU + 記憶體 + 網路速率")
    print(f"  - 統計: ✅ 每5秒性能記錄 + 封包類型統計")
    print("按 Ctrl+C 停止伺服器並生成完整報告")
    print("="*60 + "\n")
    
    # 初始化日誌文件
    try:
        import os
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server_log.txt')
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(f"{'='*80}\n")
            f.write(f"DDoS 測試伺服器日誌\n")
            f.write(f"啟動時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"端口: {port}\n")
            f.write(f"日誌位置: {log_path}\n")
            f.write(f"{'='*80}\n")
        print(f"[系統] 已初始化日誌文件: {log_path}\n")
    except Exception as e:
        print(f"[警告] 無法創建日誌文件: {e}\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n[系統] 正在關閉伺服器...")
        httpd.shutdown()
        
        # 生成最終報告
        print("[系統] 正在生成性能分析報告...")
        report_path = server_monitor.generate_final_report(
            request_count, 
            start_time, 
            os.path.dirname(os.path.abspath(__file__))
        )
        
        print("\n[系統] 伺服器已關閉")
        if report_path:
            print(f"[系統] 性能報告已保存至: {report_path}\n")
        print("[系統] 請求日誌: server_log.txt\n")

if __name__ == '__main__':
    run_server(port=8000)  # 無防禦使用 8000 端口
