"""
簡單的HTTP伺服器用於DDoS測試
僅用於教育目的和本地測試
"""
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import ThreadingMixIn
import time
import threading

request_count = 0
request_lock = threading.Lock()
start_time = time.time()

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
        with request_lock:
            request_count += 1
            current_count = request_count
        
        # 計算負載和延遲
        elapsed = time.time() - start_time
        requests_per_sec = current_count / elapsed if elapsed > 0 else 0
        
        # 根據請求速率模擬伺服器壓力
        if requests_per_sec > 100:
            delay = 0.5  # 高負載時延遲0.5秒
            status = "嚴重過載 🔴"
            status_color = "#ff0000"
        elif requests_per_sec > 50:
            delay = 0.3
            status = "過載中 🟠"
            status_color = "#ff8800"
        elif requests_per_sec > 20:
            delay = 0.1
            status = "負載偏高 🟡"
            status_color = "#ffcc00"
        else:
            delay = 0
            status = "正常運作 🟢"
            status_color = "#00ff00"
        
        time.sleep(delay)  # 模擬處理延遲
        
        # 回應請求
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        response = f"""
        <html>
        <head>
            <title>DDoS 測試伺服器</title>
            <meta http-equiv="refresh" content="1">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    margin: 0;
                }}
                .container {{
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    padding: 40px;
                    border-radius: 20px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                    text-align: center;
                    max-width: 600px;
                }}
                h1 {{
                    margin-top: 0;
                    font-size: 2.5em;
                    text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                }}
                .status {{
                    font-size: 1.5em;
                    margin: 20px 0;
                    padding: 15px;
                    background: rgba(0, 0, 0, 0.2);
                    border-radius: 10px;
                    color: {status_color};
                    font-weight: bold;
                }}
                .stats {{
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 15px;
                    margin: 20px 0;
                }}
                .stat-box {{
                    background: rgba(0, 0, 0, 0.2);
                    padding: 20px;
                    border-radius: 10px;
                }}
                .stat-value {{
                    font-size: 2em;
                    font-weight: bold;
                    color: #fff;
                }}
                .stat-label {{
                    font-size: 0.9em;
                    color: #ddd;
                    margin-top: 5px;
                }}
                .spinner {{
                    border: 8px solid rgba(255, 255, 255, 0.3);
                    border-top: 8px solid white;
                    border-radius: 50%;
                    width: 60px;
                    height: 60px;
                    animation: spin 1s linear infinite;
                    margin: 20px auto;
                    display: {('block' if delay > 0 else 'none')};
                }}
                @keyframes spin {{
                    0% {{ transform: rotate(0deg); }}
                    100% {{ transform: rotate(360deg); }}
                }}
                .loading-bar {{
                    width: 100%;
                    height: 8px;
                    background: rgba(255, 255, 255, 0.2);
                    border-radius: 4px;
                    overflow: hidden;
                    margin: 20px 0;
                }}
                .loading-progress {{
                    height: 100%;
                    background: {status_color};
                    width: {min(requests_per_sec, 100)}%;
                    transition: width 0.3s;
                    animation: pulse 1s infinite;
                }}
                @keyframes pulse {{
                    0%, 100% {{ opacity: 1; }}
                    50% {{ opacity: 0.5; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🖥️ DDoS 測試伺服器</h1>
                
                <div class="status">{status}</div>
                
                <div class="spinner"></div>
                
                <div class="loading-bar">
                    <div class="loading-progress"></div>
                </div>
                
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-value">{current_count}</div>
                        <div class="stat-label">總請求數</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{requests_per_sec:.1f}</div>
                        <div class="stat-label">請求/秒</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{delay*1000:.0f}ms</div>
                        <div class="stat-label">當前延遲</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{elapsed:.0f}s</div>
                        <div class="stat-label">運行時間</div>
                    </div>
                </div>
                
                <p style="margin-top: 30px; font-size: 0.9em; color: #ddd;">
                    ⚠️ 當請求速率超過 20/秒時伺服器會開始卡頓
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
    
    def log_message(self, format, *args):
        # 簡化日誌輸出
        if request_count % 50 == 0:  # 每50個請求才輸出一次
            print(f"[{time.strftime('%H:%M:%S')}] 請求數: {request_count}")
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
    
    print("="*60)
    print("⚠️  無防禦測試伺服器 (多線程版)")
    print("="*60)
    print(f"伺服器啟動於:")
    print(f"  - 端口: {port}")
    print(f"  - 本地: http://127.0.0.1:{port}")
    print(f"  - 局域網: http://0.0.0.0:{port}")
    print(f"  - 防禦: ❌ 無任何防禦機制")
    print(f"  - 並發: ✅ 支持多線程處理")
    print(f"  - 隊列: {httpd.request_queue_size} 個請求")
    print("按 Ctrl+C 停止伺服器")
    print("="*60 + "\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n伺服器已停止")
        httpd.shutdown()

if __name__ == '__main__':
    run_server(port=8000)  # 無防禦使用 8000 端口
