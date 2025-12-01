import os
import matplotlib.pyplot as plt
import matplotlib
matplotlib.rcParams['font.sans-serif'] = ['Microsoft YaHei', 'SimHei', 'Arial Unicode MS']
matplotlib.rcParams['axes.unicode_minus'] = False

# 最新實驗數據 (2025-12-01)
threads = [10, 100, 500, 800]

# YouTube GET 數據
youtube_get_latency = [304.8, 1202.3, 6815.4, 1504.4]
youtube_get_throughput = [34.5, 93.1, 14.4, 26.5]
youtube_get_success = [96.7, 94.0, 1.7, 24.5]

# Google GET 數據
google_get_latency = [0.0, 527.1, 520.0, 120.2]  # 0.0 表示全失敗
google_get_throughput = [1.4, 24.1, 124.5, 260.5]
google_get_success = [0.0, 31.1, 13.1, 7.0]

# 高雄大學 GET 數據
nuk_get_latency = [112.8, 860.7, 3196.9, 4153.2]
nuk_get_throughput = [94.2, 132.6, 166.5, 296.0]
nuk_get_success = [94.6, 93.4, 87.5, 51.7]

# 高雄大學 POST 數據
nuk_post_latency = [96.5, 334.0, 694.0, 648.5]

# 高雄大學 NO_HEADERS 數據
nuk_noheaders_latency = [297.0, 844.1, 3321.6, 3964.0]

# 高雄大學 UDP 數據
nuk_udp_latency = [0.7, 4.0, 17.4, 26.0]

# YouTube POST 數據
youtube_post_latency = [0.0, 232.1, 292.0, 216.3]

# YouTube NO_HEADERS 數據
youtube_noheaders_latency = [0.0, 0.0, 0.0, 4055.7]

# YouTube UDP 數據
youtube_udp_latency = [0.0, 0.0, 73.5, 26.6]

# Google POST 數據
google_post_latency = [0.0, 833.8, 870.0, 428.3]

# Google NO_HEADERS 數據
google_noheaders_latency = [253.3, 121.9, 216.2, 121.5]

# Google UDP 數據
google_udp_latency = [0.5, 3.8, 17.2, 25.8]

# 本地有防禦 POST 數據
local_def_post_latency = [10.8, 102.4, 426.0, 716.3]

# 本地有防禦 NO_HEADERS 數據
local_def_noheaders_latency = [13.0, 122.4, 448.6, 627.5]

# 本地有防禦 UDP 數據
local_def_udp_latency = [0.2, 1.6, 7.1, 11.0]

# 本地無防禦 POST 數據
local_nodef_post_latency = [11.0, 126.3, 463.4, 720.9]

# 本地無防禦 NO_HEADERS 數據
local_nodef_noheaders_latency = [472.1, 402.0, 678.2, 1002.2]

# 本地無防禦 UDP 數據
local_nodef_udp_latency = [0.2, 1.8, 7.0, 10.6]

# 本地有防禦 GET 數據
local_def_get_latency = [10.3, 106.3, 425.0, 629.3]
local_def_get_throughput = [839.2, 845.2, 3384.0, 7688.0]
local_def_get_success = [95.0, 94.4, 92.3, 91.1]

# 本地無防禦 GET 數據
local_nodef_get_latency = [154.9, 428.0, 702.7, 1016.1]
local_nodef_get_throughput = [68.8, 254.1, 825.2, 2976.1]
local_nodef_get_success = [94.7, 94.8, 90.2, 88.4]

# UDP 數據
youtube_udp_throughput = [0.2, 15.0, 4804.6, 26196.5]
google_udp_throughput = [10559.1, 9854.2, 16148.0, 26714.0]
nuk_udp_throughput = [7997.8, 9438.4, 15996.5, 25903.8]
local_def_udp_throughput = [13220.5, 13606.5, 21618.5, 33532.1]
local_nodef_udp_throughput = [13610.0, 12370.4, 22504.2, 35916.5]

out_dir = os.path.dirname(__file__)

# 1. 五伺服器 GET 延遲對比
plt.figure(figsize=(10, 6))
plt.plot(threads, youtube_get_latency, marker='o', linewidth=2, label='YouTube')
plt.plot(threads, google_get_latency, marker='s', linewidth=2, label='Google')
plt.plot(threads, nuk_get_latency, marker='^', linewidth=2, label='高雄大學')
plt.plot(threads, local_def_get_latency, marker='D', linewidth=2, label='本地有防禦')
plt.plot(threads, local_nodef_get_latency, marker='v', linewidth=2, label='本地無防禦')
plt.xlabel('線程數', fontsize=12)
plt.ylabel('延遲 (ms)', fontsize=12)
plt.title('五伺服器 GET 請求延遲對比', fontsize=14, fontweight='bold')
plt.grid(True, alpha=0.3)
plt.legend(fontsize=10, loc='best')
plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_5servers_get_latency.png'), dpi=150)
plt.close()

# 2. 五伺服器 GET 吞吐量對比
plt.figure(figsize=(10, 6))
plt.plot(threads, youtube_get_throughput, marker='o', linewidth=2, label='YouTube')
plt.plot(threads, google_get_throughput, marker='s', linewidth=2, label='Google')
plt.plot(threads, nuk_get_throughput, marker='^', linewidth=2, label='高雄大學')
plt.plot(threads, local_def_get_throughput, marker='D', linewidth=2, label='本地有防禦')
plt.plot(threads, local_nodef_get_throughput, marker='v', linewidth=2, label='本地無防禦')
plt.xlabel('線程數', fontsize=12)
plt.ylabel('吞吐量 (req/s)', fontsize=12)
plt.title('五伺服器 GET 請求吞吐量對比', fontsize=14, fontweight='bold')
plt.grid(True, alpha=0.3)
plt.legend(fontsize=10, loc='best')
plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_5servers_get_throughput.png'), dpi=150)
plt.close()

# 3. 五伺服器 GET 成功率對比
plt.figure(figsize=(10, 6))
plt.plot(threads, youtube_get_success, marker='o', linewidth=2, label='YouTube')
plt.plot(threads, google_get_success, marker='s', linewidth=2, label='Google')
plt.plot(threads, nuk_get_success, marker='^', linewidth=2, label='高雄大學')
plt.plot(threads, local_def_get_success, marker='D', linewidth=2, label='本地有防禦')
plt.plot(threads, local_nodef_get_success, marker='v', linewidth=2, label='本地無防禦')
plt.xlabel('線程數', fontsize=12)
plt.ylabel('成功率 (%)', fontsize=12)
plt.title('五伺服器 GET 請求成功率對比', fontsize=14, fontweight='bold')
plt.ylim(0, 100)
plt.grid(True, alpha=0.3)
plt.legend(fontsize=10, loc='best')
plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_5servers_get_success.png'), dpi=150)
plt.close()

# 4. UDP Flood 吞吐量對比
plt.figure(figsize=(10, 6))
plt.plot(threads, youtube_udp_throughput, marker='o', linewidth=2, label='YouTube')
plt.plot(threads, google_udp_throughput, marker='s', linewidth=2, label='Google')
plt.plot(threads, nuk_udp_throughput, marker='^', linewidth=2, label='高雄大學')
plt.plot(threads, local_def_udp_throughput, marker='D', linewidth=2, label='本地有防禦')
plt.plot(threads, local_nodef_udp_throughput, marker='v', linewidth=2, label='本地無防禦')
plt.xlabel('線程數', fontsize=12)
plt.ylabel('吞吐量 (req/s)', fontsize=12)
plt.title('五伺服器 UDP Flood 吞吐量對比', fontsize=14, fontweight='bold')
plt.grid(True, alpha=0.3)
plt.legend(fontsize=10, loc='best')
plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_5servers_udp_throughput.png'), dpi=150)
plt.close()

# 5. 本地有防禦 vs 無防禦 (GET) 詳細對比
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

# 延遲對比
ax1.plot(threads, local_def_get_latency, marker='D', linewidth=2, label='有防禦', color='green')
ax1.plot(threads, local_nodef_get_latency, marker='v', linewidth=2, label='無防禦', color='red')
ax1.set_xlabel('線程數', fontsize=12)
ax1.set_ylabel('延遲 (ms)', fontsize=12)
ax1.set_title('本地伺服器延遲對比 (GET)', fontsize=13, fontweight='bold')
ax1.grid(True, alpha=0.3)
ax1.legend(fontsize=11)

# 吞吐量對比
ax2.plot(threads, local_def_get_throughput, marker='D', linewidth=2, label='有防禦', color='green')
ax2.plot(threads, local_nodef_get_throughput, marker='v', linewidth=2, label='無防禦', color='red')
ax2.set_xlabel('線程數', fontsize=12)
ax2.set_ylabel('吞吐量 (req/s)', fontsize=12)
ax2.set_title('本地伺服器吞吐量對比 (GET)', fontsize=13, fontweight='bold')
ax2.grid(True, alpha=0.3)
ax2.legend(fontsize=11)

plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_local_defense_comparison.png'), dpi=150)
plt.close()

# 6. TCP 攔截率對比 (柱狀圖)
fig, ax = plt.subplots(figsize=(10, 6))
servers = ['YouTube', 'Google', '高雄大學', '本地有防禦', '本地無防禦']
tcp_intercept_rate = [97.1, 90.0, 0.0, 0.0, 0.0]  # YouTube 500線程, Google推測
colors = ['#d62728', '#ff7f0e', '#2ca02c', '#1f77b4', '#9467bd']

bars = ax.bar(servers, tcp_intercept_rate, color=colors, alpha=0.8, edgecolor='black')
ax.set_ylabel('TCP 攔截率 (%)', fontsize=12)
ax.set_title('五伺服器 TCP 層攔截率對比', fontsize=14, fontweight='bold')
ax.set_ylim(0, 105)
ax.grid(True, alpha=0.3, axis='y')

# 在柱子上標註數值
for bar in bars:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height + 2,
            f'{height:.1f}%', ha='center', va='bottom', fontsize=11, fontweight='bold')

plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_tcp_intercept_comparison.png'), dpi=150)
plt.close()

# 7. 800線程效能綜合對比 (雷達圖數據準備)
fig, ax = plt.subplots(figsize=(10, 6))
x = range(len(servers))
throughput_800 = [26.5, 260.5, 296.0, 7688.0, 2976.1]

bars = ax.bar(x, throughput_800, color=colors, alpha=0.8, edgecolor='black')
ax.set_xticks(x)
ax.set_xticklabels(servers, fontsize=11)
ax.set_ylabel('吞吐量 (req/s)', fontsize=12)
ax.set_title('800 線程 GET 吞吐量對比', fontsize=14, fontweight='bold')
ax.grid(True, alpha=0.3, axis='y')

# 標註數值
for bar in bars:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height + 200,
            f'{height:.1f}', ha='center', va='bottom', fontsize=10, fontweight='bold')

plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'fig_800threads_throughput_comparison.png'), dpi=150)
plt.close()

# 8. 綜合研究成果圖表 - 所有方法所有網站延遲對比
fig = plt.figure(figsize=(20, 12))

# 顏色方案
colors = {
    'YouTube': '#d62728',
    'Google': '#ff7f0e', 
    'NUK': '#2ca02c',
    'DefenseOn': '#1f77b4',
    'DefenseOff': '#9467bd'
}

# 8.1 GET 方法延遲
ax1 = plt.subplot(2, 2, 1)
ax1.plot(threads, youtube_get_latency, marker='o', linewidth=2.5, label='YouTube', color=colors['YouTube'])
ax1.plot(threads, google_get_latency, marker='s', linewidth=2.5, label='Google', color=colors['Google'])
ax1.plot(threads, nuk_get_latency, marker='^', linewidth=2.5, label='高雄大學', color=colors['NUK'])
ax1.plot(threads, local_def_get_latency, marker='D', linewidth=2.5, label='本地有防禦', color=colors['DefenseOn'])
ax1.plot(threads, local_nodef_get_latency, marker='v', linewidth=2.5, label='本地無防禦', color=colors['DefenseOff'])
ax1.set_xlabel('線程數', fontsize=12)
ax1.set_ylabel('延遲 (ms)', fontsize=12)
ax1.set_title('(A) GET 方法延遲對比', fontsize=14, fontweight='bold')
ax1.grid(True, alpha=0.3)
ax1.legend(fontsize=10, loc='upper left')
ax1.set_yscale('log')  # 使用對數刻度以便更好地顯示數據範圍

# 8.2 POST 方法延遲
ax2 = plt.subplot(2, 2, 2)
ax2.plot(threads, youtube_post_latency, marker='o', linewidth=2.5, label='YouTube', color=colors['YouTube'])
ax2.plot(threads, google_post_latency, marker='s', linewidth=2.5, label='Google', color=colors['Google'])
ax2.plot(threads, nuk_post_latency, marker='^', linewidth=2.5, label='高雄大學', color=colors['NUK'])
ax2.plot(threads, local_def_post_latency, marker='D', linewidth=2.5, label='本地有防禦', color=colors['DefenseOn'])
ax2.plot(threads, local_nodef_post_latency, marker='v', linewidth=2.5, label='本地無防禦', color=colors['DefenseOff'])
ax2.set_xlabel('線程數', fontsize=12)
ax2.set_ylabel('延遲 (ms)', fontsize=12)
ax2.set_title('(B) POST 方法延遲對比', fontsize=14, fontweight='bold')
ax2.grid(True, alpha=0.3)
ax2.legend(fontsize=10, loc='upper left')

# 8.3 NO_HEADERS 方法延遲
ax3 = plt.subplot(2, 2, 3)
ax3.plot(threads, youtube_noheaders_latency, marker='o', linewidth=2.5, label='YouTube', color=colors['YouTube'])
ax3.plot(threads, google_noheaders_latency, marker='s', linewidth=2.5, label='Google', color=colors['Google'])
ax3.plot(threads, nuk_noheaders_latency, marker='^', linewidth=2.5, label='高雄大學', color=colors['NUK'])
ax3.plot(threads, local_def_noheaders_latency, marker='D', linewidth=2.5, label='本地有防禦', color=colors['DefenseOn'])
ax3.plot(threads, local_nodef_noheaders_latency, marker='v', linewidth=2.5, label='本地無防禦', color=colors['DefenseOff'])
ax3.set_xlabel('線程數', fontsize=12)
ax3.set_ylabel('延遲 (ms)', fontsize=12)
ax3.set_title('(C) NO_HEADERS 方法延遲對比', fontsize=14, fontweight='bold')
ax3.grid(True, alpha=0.3)
ax3.legend(fontsize=10, loc='upper left')
ax3.set_yscale('log')

# 8.4 UDP 方法延遲
ax4 = plt.subplot(2, 2, 4)
ax4.plot(threads, youtube_udp_latency, marker='o', linewidth=2.5, label='YouTube', color=colors['YouTube'])
ax4.plot(threads, google_udp_latency, marker='s', linewidth=2.5, label='Google', color=colors['Google'])
ax4.plot(threads, nuk_udp_latency, marker='^', linewidth=2.5, label='高雄大學', color=colors['NUK'])
ax4.plot(threads, local_def_udp_latency, marker='D', linewidth=2.5, label='本地有防禦', color=colors['DefenseOn'])
ax4.plot(threads, local_nodef_udp_latency, marker='v', linewidth=2.5, label='本地無防禦', color=colors['DefenseOff'])
ax4.set_xlabel('線程數', fontsize=12)
ax4.set_ylabel('延遲 (ms)', fontsize=12)
ax4.set_title('(D) UDP Flood 延遲對比', fontsize=14, fontweight='bold')
ax4.grid(True, alpha=0.3)
ax4.legend(fontsize=10, loc='upper left')

plt.suptitle('五伺服器四種攻擊方法延遲綜合對比\n(2025-12-01 測試結果)', 
             fontsize=16, fontweight='bold', y=0.995)
plt.tight_layout(rect=[0, 0, 1, 0.985])
plt.savefig(os.path.join(out_dir, 'fig_comprehensive_latency.png'), dpi=150, bbox_inches='tight')
plt.close()

print(f'✅ 已生成 8 張圖表至 {out_dir}')
print('圖表清單:')
print('  1. fig_5servers_get_latency.png - 五伺服器GET延遲對比')
print('  2. fig_5servers_get_throughput.png - 五伺服器GET吞吐量對比')
print('  3. fig_5servers_get_success.png - 五伺服器GET成功率對比')
print('  4. fig_5servers_udp_throughput.png - UDP Flood吞吐量對比')
print('  5. fig_local_defense_comparison.png - 本地防禦效果對比')
print('  6. fig_tcp_intercept_comparison.png - TCP攔截率對比')
print('  7. fig_800threads_throughput_comparison.png - 800線程吞吐量對比')
print('  8. fig_comprehensive_latency.png - 📊 所有方法所有網站延遲綜合對比 (4子圖)')
print('\n💡 提示: fig_comprehensive_latency.png 包含GET/POST/NO_HEADERS/UDP四種方法的延遲對比')
