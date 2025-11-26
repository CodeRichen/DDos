"""
HTML 模板渲染模組
負責生成動態網頁內容
"""
import os
import server_monitor

def load_template(template_name):
    """載入 HTML 模板"""
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    template_path = os.path.join(template_dir, template_name)
    
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return None

def render_dashboard(data):
    """
    渲染無防禦伺服器的儀表板
    data: 包含所有需要顯示的數據字典
    """
    template = load_template('dashboard.html')
    if not template:
        return generate_fallback_dashboard(data)
    
    # 生成封包特徵 HTML
    features = data.get('packet_features', {})
    features_html = f"""
        <div class="feature-box">
            <strong>請求方法:</strong> {features.get('method', 'N/A')}<br>
            <strong>路徑類型:</strong> {features.get('path_type', 'N/A')}<br>
            <strong>需要解析主體:</strong> {'是' if features.get('requires_parsing') else '否'}<br>
            <strong>需要處理邏輯:</strong> {'是' if features.get('requires_processing') else '否'}<br>
            <strong>需要生成響應:</strong> {'是' if features.get('requires_response') else '否'}
        </div>
    """
    
    # 生成標頭 HTML
    headers_html = ""
    for key, value in data.get('headers', {}).items():
        headers_html += f'<div class="header-item"><strong>{key}:</strong> {value}</div>'
    
    # 生成操作列表 HTML
    actions_html = ""
    for action in data.get('actions', []):
        actions_html += f'<div class="action-item">✓ {action}</div>'
    
    # 生成最近日誌 HTML
    recent_logs_html = data.get('recent_logs_html', '<div>暫無記錄</div>')
    
    # 替換所有佔位符
    template = template.replace('{{STATUS}}', data.get('status', ''))
    template = template.replace('{{STATUS_COLOR}}', data.get('status_color', '#00ff00'))
    template = template.replace('{{TOTAL_REQUESTS}}', str(data.get('total_requests', 0)))
    template = template.replace('{{REQUESTS_PER_SEC}}', f"{data.get('requests_per_sec', 0):.1f}")
    template = template.replace('{{CPU_PERCENT}}', f"{data.get('cpu_percent', 0):.1f}%")
    template = template.replace('{{MEMORY_PERCENT}}', f"{data.get('memory_percent', 0):.1f}%")
    template = template.replace('{{NETWORK_SENT}}', data.get('network_sent', '0 B/s'))
    template = template.replace('{{NETWORK_RECV}}', data.get('network_recv', '0 B/s'))
    template = template.replace('{{DELAY}}', f"{data.get('delay', 0)}ms")
    template = template.replace('{{UPTIME}}', f"{data.get('uptime', 0):.0f}s")
    template = template.replace('{{CLIENT_IP}}', data.get('client_ip', ''))
    template = template.replace('{{METHOD}}', data.get('method', ''))
    template = template.replace('{{PATH}}', data.get('path', ''))
    template = template.replace('{{TIMESTAMP}}', data.get('timestamp', ''))
    template = template.replace('{{PACKET_FEATURES}}', features_html)
    template = template.replace('{{HEADERS}}', headers_html)
    template = template.replace('{{ACTIONS}}', actions_html)
    template = template.replace('{{RECENT_LOGS}}', recent_logs_html)
    
    return template

def render_defense_dashboard(data):
    """
    渲染防禦伺服器的儀表板
    data: 包含所有需要顯示的數據字典
    """
    template = load_template('dashboard_defense.html')
    if not template:
        return generate_fallback_defense_dashboard(data)
    
    # 生成防禦機制列表
    mechanisms_html = ""
    for mechanism in data.get('defense_mechanisms', []):
        mechanisms_html += f'<div class="defense-item">✓ {mechanism}</div>'
    
    # 生成黑名單 IP 列表
    blacklist_html = ""
    blacklist = data.get('blacklist_ips', [])
    if blacklist:
        for ip_info in blacklist:
            blacklist_html += f'<div class="ip-item">🚫 {ip_info}</div>'
    else:
        blacklist_html = '<div style="text-align: center; color: #aaa;">黑名單為空</div>'
    
    # 生成攔截日誌
    blocked_logs_html = ""
    for log in data.get('blocked_logs', []):
        blocked_logs_html += f'<div class="log-entry blocked-item">{log}</div>'
    if not blocked_logs_html:
        blocked_logs_html = '<div style="text-align: center; color: #aaa;">暫無攔截記錄</div>'
    
    # 生成允許日誌
    allowed_logs_html = ""
    for log in data.get('allowed_logs', []):
        allowed_logs_html += f'<div class="log-entry">{log}</div>'
    if not allowed_logs_html:
        allowed_logs_html = '<div style="text-align: center; color: #aaa;">暫無允許記錄</div>'
    
    # 判斷是否需要警告樣式
    blocked_class = 'alert' if data.get('blocked_requests', 0) > 100 else ''
    
    # 替換所有佔位符
    template = template.replace('{{STATUS}}', data.get('status', ''))
    template = template.replace('{{STATUS_COLOR}}', data.get('status_color', '#00ff00'))
    template = template.replace('{{TOTAL_REQUESTS}}', str(data.get('total_requests', 0)))
    template = template.replace('{{BLOCKED_REQUESTS}}', str(data.get('blocked_requests', 0)))
    template = template.replace('{{ALLOWED_REQUESTS}}', str(data.get('allowed_requests', 0)))
    template = template.replace('{{REQUESTS_PER_SEC}}', f"{data.get('requests_per_sec', 0):.1f}/s")
    template = template.replace('{{NETWORK_SENT_RATE}}', server_monitor.format_bytes(data.get('network_sent_rate', 0)) + '/s')
    template = template.replace('{{CPU_PERCENT}}', f"{data.get('cpu_percent', 0):.1f}%")
    template = template.replace('{{MEMORY_PERCENT}}', f"{data.get('memory_percent', 0):.1f}%")
    template = template.replace('{{BLACKLIST_COUNT}}', str(data.get('blacklist_count', 0)))
    template = template.replace('{{UPTIME}}', f"{data.get('uptime', 0):.0f}s")
    template = template.replace('{{BLOCKED_CLASS}}', blocked_class)
    template = template.replace('{{DEFENSE_MECHANISMS}}', mechanisms_html)
    template = template.replace('{{BLACKLIST_IPS}}', blacklist_html)
    template = template.replace('{{BLOCKED_LOGS}}', blocked_logs_html)
    template = template.replace('{{ALLOWED_LOGS}}', allowed_logs_html)
    
    return template

def generate_fallback_dashboard(data):
    """生成後備的簡單 HTML (當模板文件不存在時)"""
    return f"""
    <html>
    <head><title>DDoS 測試伺服器</title></head>
    <body style="font-family: Arial; padding: 20px;">
        <h1>DDoS 測試伺服器</h1>
        <p>狀態: {data.get('status', 'Unknown')}</p>
        <p>總請求數: {data.get('total_requests', 0)}</p>
        <p>請求速率: {data.get('requests_per_sec', 0):.1f} req/s</p>
        <p>CPU: {data.get('cpu_percent', 0):.1f}%</p>
        <p>記憶體: {data.get('memory_percent', 0):.1f}%</p>
        <p><em>模板文件未找到,使用後備顯示</em></p>
    </body>
    </html>
    """

def generate_fallback_defense_dashboard(data):
    """生成後備的防禦伺服器 HTML"""
    return f"""
    <html>
    <head><title>DDoS 防禦伺服器</title></head>
    <body style="font-family: Arial; padding: 20px;">
        <h1>DDoS 防禦伺服器</h1>
        <p>狀態: {data.get('status', 'Unknown')}</p>
        <p>總請求數: {data.get('total_requests', 0)}</p>
        <p>已攔截: {data.get('blocked_requests', 0)}</p>
        <p>已允許: {data.get('allowed_requests', 0)}</p>
        <p>黑名單 IP: {data.get('blacklist_count', 0)}</p>
        <p><em>模板文件未找到,使用後備顯示</em></p>
    </body>
    </html>
    """

def render_monitor_dashboard(data):
    """
    渲染實時監控儀表板
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
    """
    template = load_template('monitor_dashboard.html')
    if not template:
        return generate_fallback_monitor_dashboard(data)
    
    request_rate = data.get('request_rate', 0)
    avg_delay = data.get('avg_delay', 0)
    request_count = data.get('request_count', 0)
    blocked_count = data.get('blocked_count', 0)
    cpu_percent = data.get('cpu_percent', 0)
    memory_percent = data.get('memory_percent', 0)
    network_sent_rate = data.get('network_sent_rate', 0)
    network_recv_rate = data.get('network_recv_rate', 0)
    uptime = data.get('uptime', 0)
    
    # 計算衍生數據
    total_requests = request_count + blocked_count
    block_rate = (blocked_count / total_requests * 100) if total_requests > 0 else 0
    avg_delay_ms = avg_delay * 1000  # 轉換為毫秒
    
    # 請求速率狀態
    if request_rate < 50:
        rate_status_class = 'good'
        rate_status_text = '正常'
    elif request_rate < 150:
        rate_status_class = 'warning'
        rate_status_text = '繁忙'
    else:
        rate_status_class = 'critical'
        rate_status_text = '高負載'
    
    # 延遲狀態
    if avg_delay < 0.1:
        delay_status_class = 'good'
        delay_status_text = '快速'
    elif avg_delay < 0.5:
        delay_status_class = 'warning'
        delay_status_text = '正常'
    else:
        delay_status_class = 'critical'
        delay_status_text = '緩慢'
    
    # CPU 狀態
    cpu_status_class = ''
    if cpu_percent > 80:
        cpu_status_class = 'danger'
    elif cpu_percent > 50:
        cpu_status_class = 'warning'
    
    # 記憶體狀態
    memory_status_class = ''
    if memory_percent > 85:
        memory_status_class = 'danger'
    elif memory_percent > 60:
        memory_status_class = 'warning'
    
    # 運行時間格式化
    uptime_str = f"{int(uptime//60)}:{int(uptime%60):02d}"
    
    # 替換模板變數
    template = template.replace('{{request_rate}}', f"{request_rate:.1f}")
    template = template.replace('{{rate_status_class}}', rate_status_class)
    template = template.replace('{{rate_status_text}}', rate_status_text)
    template = template.replace('{{avg_delay}}', f"{avg_delay_ms:.1f}")
    template = template.replace('{{delay_status_class}}', delay_status_class)
    template = template.replace('{{delay_status_text}}', delay_status_text)
    template = template.replace('{{request_count}}', str(request_count))
    template = template.replace('{{blocked_count}}', str(blocked_count))
    template = template.replace('{{block_rate}}', f"{block_rate:.1f}")
    template = template.replace('{{cpu_percent}}', f"{cpu_percent:.1f}")
    template = template.replace('{{cpu_status_class}}', cpu_status_class)
    template = template.replace('{{cpu_width}}', f"{min(cpu_percent, 100):.1f}")
    template = template.replace('{{memory_percent}}', f"{memory_percent:.1f}")
    template = template.replace('{{memory_status_class}}', memory_status_class)
    template = template.replace('{{memory_width}}', f"{min(memory_percent, 100):.1f}")
    template = template.replace('{{network_sent}}', f"{network_sent_rate/1024:.1f}")
    template = template.replace('{{network_recv}}', f"{network_recv_rate/1024:.1f}")
    template = template.replace('{{uptime}}', uptime_str)
    
    return template

def generate_fallback_monitor_dashboard(data):
    """生成後備的監控儀表板 HTML"""
    return f"""
    <html>
    <head>
        <title>伺服器實時監控</title>
        <meta http-equiv="refresh" content="2">
    </head>
    <body style="font-family: Arial; padding: 20px; background: #2a5298; color: white;">
        <h1>🛡️ DDoS 防禦伺服器 - 實時監控</h1>
        <p>請求速率: {data.get('request_rate', 0):.1f} 請求/秒</p>
        <p>平均延遲: {data.get('avg_delay', 0)*1000:.1f} ms</p>
        <p>總請求數: {data.get('request_count', 0)}</p>
        <p>攔截數: {data.get('blocked_count', 0)}</p>
        <p>CPU: {data.get('cpu_percent', 0):.1f}%</p>
        <p>記憶體: {data.get('memory_percent', 0):.1f}%</p>
        <p>網路發送: {data.get('network_sent_rate', 0)/1024:.1f} KB/s</p>
        <p>網路接收: {data.get('network_recv_rate', 0)/1024:.1f} KB/s</p>
        <p><em>模板文件未找到,使用後備顯示</em></p>
        <p><a href="/" style="color: #4ade80;">返回首頁</a></p>
    </body>
    </html>
    """

