"""
監控儀表板 HTML 模板
"""

def render_monitor_dashboard(data):
    """
    渲染實時監控儀表板
    
    Args:
        data: 包含監控數據的字典
            - request_rate: 請求速率
            - avg_delay: 平均延遲 (秒)
            - request_count: 總請求數
            - blocked_count: 攔截數
            - cpu_percent: CPU 使用率
            - memory_percent: 記憶體使用率
            - network_sent_rate: 網路發送速率 (bytes/s)
            - network_recv_rate: 網路接收速率 (bytes/s)
            - uptime: 運行時間 (秒)
    
    Returns:
        str: HTML 內容
    """
    request_rate = data.get('request_rate', 0)
    avg_delay = data.get('avg_delay', 0)
    request_count = data.get('request_count', 0)
    blocked_count = data.get('blocked_count', 0)
    cpu_percent = data.get('cpu_percent', 0)
    memory_percent = data.get('memory_percent', 0)
    network_sent_rate = data.get('network_sent_rate', 0)
    network_recv_rate = data.get('network_recv_rate', 0)
    uptime = data.get('uptime', 0)
    
    # 計算攔截率
    total_requests = request_count + blocked_count
    block_rate = (blocked_count / total_requests * 100) if total_requests > 0 else 0
    
    # 延遲轉換為毫秒
    avg_delay_ms = avg_delay * 1000
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="2">
    <title>伺服器實時監控</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        h1 {{
            text-align: center;
            margin-bottom: 30px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .card {{
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid rgba(255,255,255,0.2);
        }}
        .card h2 {{
            font-size: 1.2em;
            margin-bottom: 15px;
            color: #a8dadc;
        }}
        .metric {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .label {{
            font-size: 0.9em;
            color: #e0e0e0;
            margin-top: 5px;
        }}
        .progress-bar {{
            width: 100%;
            height: 30px;
            background: rgba(0,0,0,0.3);
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #4ade80, #22c55e);
            transition: width 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.9em;
            font-weight: bold;
        }}
        .progress-fill.warning {{
            background: linear-gradient(90deg, #fbbf24, #f59e0b);
        }}
        .progress-fill.danger {{
            background: linear-gradient(90deg, #f87171, #ef4444);
        }}
        .status {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            margin-top: 10px;
        }}
        .status.good {{ background: #22c55e; }}
        .status.warning {{ background: #f59e0b; }}
        .status.critical {{ background: #ef4444; }}
        .info-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-top: 15px;
        }}
        .info-item {{
            background: rgba(0,0,0,0.2);
            padding: 15px;
            border-radius: 10px;
        }}
        .info-item .value {{
            font-size: 1.5em;
            font-weight: bold;
            color: #4ade80;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            background: rgba(0,0,0,0.2);
            border-radius: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ DDoS 防禦伺服器 - 實時監控儀表板</h1>
        
        <div class="grid">
            <div class="card">
                <h2>⚡ 請求速率</h2>
                <div class="metric">{request_rate:.1f}</div>
                <div class="label">請求/秒</div>
                <div class="status {'good' if request_rate < 50 else 'warning' if request_rate < 150 else 'critical'}">
                    {'正常' if request_rate < 50 else '繁忙' if request_rate < 150 else '高負載'}
                </div>
            </div>
            
            <div class="card">
                <h2>⏱️ 平均延遲</h2>
                <div class="metric">{avg_delay_ms:.1f}</div>
                <div class="label">毫秒 (ms)</div>
                <div class="status {'good' if avg_delay < 0.1 else 'warning' if avg_delay < 0.5 else 'critical'}">
                    {'快速' if avg_delay < 0.1 else '正常' if avg_delay < 0.5 else '緩慢'}
                </div>
            </div>
            
            <div class="card">
                <h2>🔢 總請求數</h2>
                <div class="metric">{request_count}</div>
                <div class="label">次請求</div>
                <div class="info-grid" style="margin-top: 15px;">
                    <div>
                        <div style="color: #4ade80;">允許: {request_count}</div>
                    </div>
                    <div>
                        <div style="color: #ef4444;">攔截: {blocked_count}</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>📊 攔截率</h2>
                <div class="metric">{block_rate:.1f}%</div>
                <div class="label">防禦效率</div>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>💻 CPU 使用率</h2>
                <div class="progress-bar">
                    <div class="progress-fill {'warning' if cpu_percent > 50 else 'danger' if cpu_percent > 80 else ''}" 
                         style="width: {min(cpu_percent, 100):.1f}%">
                        {cpu_percent:.1f}%
                    </div>
                </div>
                <div class="label">處理器負載</div>
            </div>
            
            <div class="card">
                <h2>🧠 記憶體使用率</h2>
                <div class="progress-bar">
                    <div class="progress-fill {'warning' if memory_percent > 60 else 'danger' if memory_percent > 85 else ''}" 
                         style="width: {min(memory_percent, 100):.1f}%">
                        {memory_percent:.1f}%
                    </div>
                </div>
                <div class="label">記憶體負載</div>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>🌐 網路流量</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="label">發送速率</div>
                        <div class="value">{network_sent_rate/1024:.1f} KB/s</div>
                    </div>
                    <div class="info-item">
                        <div class="label">接收速率</div>
                        <div class="value">{network_recv_rate/1024:.1f} KB/s</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>⏰ 運行時間</h2>
                <div class="metric">{int(uptime//60)}:{int(uptime%60):02d}</div>
                <div class="label">分:秒</div>
            </div>
        </div>
        
        <div class="footer">
            <p>頁面每 2 秒自動刷新 | <a href="/" style="color: #4ade80;">返回首頁</a></p>
        </div>
    </div>
</body>
</html>"""
    
    return html
