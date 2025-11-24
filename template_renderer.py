"""
HTML 模板渲染模組
負責生成動態網頁內容
"""
import os

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
