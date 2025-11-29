import os
import matplotlib.pyplot as plt

# 固定資料：從實驗摘要擷取（可改為解析 report.txt）
threads = [10, 20, 30, 50, 75, 100, 150, 200, 300]

# GET（無防禦）
get_latency = [87.1, 227.7, 298.0, 309.7, 311.4, 385.3, 515.0, 520.0, 559.4]
get_throughput = [115.8, 89.9, 103.2, 165.8, 246.5, 268.8, 300.0, 401.4, 566.2]

# POST（修正後）
post_latency = [10.9, 32.3, 35.4, 75.2, 94.5, 134.4, 218.4, 210.2, 308.3]
post_throughput = [920.9, 623.0, 855.8, 678.8, 827.2, 819.4, 852.4, 1237.2, 1681.0]

# NO_HEADERS（無防禦）
noh_latency = [104.4, 250.1, 299.8, 310.3, 309.6, 409.5, 511.0, 513.5, 514.8]
noh_throughput = [98.5, 82.0, 102.5, 164.4, 249.0, 253.4, 300.4, 402.1, 607.4]

# 防禦開啟（GET/POST/NO_HEADERS 節錄、以主要點描繪）
threads_def = [10, 50, 100, 200, 300]
get_def_latency = [11.1, 49.4, 100.1, 189.8, 259.1]
get_def_throughput = [901.1, 1032.4, 1088.8, 1413.4, 2057.9]

post_def_latency = [25.4, 76.2, 167.5, 276.0, 398.6]
post_def_throughput = [395.0, 683.2, 676.8, 1142.2, 1875.0]

noh_def_latency = [26.1, 68.8, 163.3, 299.8, 594.5]
noh_def_throughput = [388.1, 707.4, 697.2, 1222.4, 1577.9]

out_dir = os.path.dirname(__file__)

plt.figure(figsize=(8,5))
plt.plot(threads, get_latency, marker='o', label='GET (no defense)')
plt.plot(threads_def, get_def_latency, marker='o', label='GET (defense)')
plt.xlabel('Threads')
plt.ylabel('Latency (ms)')
plt.title('Latency vs Threads (GET)')
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_latency_get.png'), dpi=150)

plt.figure(figsize=(8,5))
plt.plot(threads, get_throughput, marker='o', label='GET (no defense)')
plt.plot(threads_def, get_def_throughput, marker='o', label='GET (defense)')
plt.xlabel('Threads')
plt.ylabel('Throughput (req/s)')
plt.title('Throughput vs Threads (GET)')
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_throughput_get.png'), dpi=150)

plt.figure(figsize=(8,5))
plt.plot(threads, post_latency, marker='o', label='POST (fixed)')
plt.plot(threads_def, post_def_latency, marker='o', label='POST (defense)')
plt.xlabel('Threads')
plt.ylabel('Latency (ms)')
plt.title('Latency vs Threads (POST)')
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_latency_post.png'), dpi=150)

plt.figure(figsize=(8,5))
plt.plot(threads, post_throughput, marker='o', label='POST (fixed)')
plt.plot(threads_def, post_def_throughput, marker='o', label='POST (defense)')
plt.xlabel('Threads')
plt.ylabel('Throughput (req/s)')
plt.title('Throughput vs Threads (POST)')
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_throughput_post.png'), dpi=150)

plt.figure(figsize=(8,5))
plt.plot(threads, noh_latency, marker='o', label='NO_HEADERS (no defense)')
plt.plot(threads_def, noh_def_latency, marker='o', label='NO_HEADERS (defense)')
plt.xlabel('Threads')
plt.ylabel('Latency (ms)')
plt.title('Latency vs Threads (NO_HEADERS)')
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_latency_noh.png'), dpi=150)

plt.figure(figsize=(8,5))
plt.plot(threads, noh_throughput, marker='o', label='NO_HEADERS (no defense)')
plt.plot(threads_def, noh_def_throughput, marker='o', label='NO_HEADERS (defense)')
plt.xlabel('Threads')
plt.ylabel('Throughput (req/s)')
plt.title('Throughput vs Threads (NO_HEADERS)')
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_throughput_noh.png'), dpi=150)

print('Saved charts to', out_dir)
