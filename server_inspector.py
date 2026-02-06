#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
服务器自动化巡检脚本 (Python 2.7 兼容版本)
功能：对指定服务器进行SSH连接，检查主机资源和进程状态，自动标记异常主机，并通过邮件发送HTML报告
"""

from __future__ import print_function, unicode_literals

import os
import sys
import smtplib
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import paramiko


# ==================== 配置常量 ====================
THRESHOLDS = {
    "disk_percent": 85,      # 磁盘使用率阈值 %
    "memory_percent": 95,    # 内存使用率阈值 %
    "cpu_percent": 80,       # CPU使用率阈值 %
    "ssh_timeout": 60,       # SSH连接超时时间（秒）
}


class ServerConfig(object):
    """服务器配置"""
    
    def __init__(self, host, port=22, username="root", password=None, key_file=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file


class InspectionResult(object):
    """巡检结果"""
    
    def __init__(self, host):
        self.host = host
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.success = True
        self.score = 100  # 健康评分，满分100
        
        # 资源使用情况
        self.cpu_percent = None
        self.memory_percent = None
        self.disk_usage = None  # {挂载点: 使用率}
        self.zombie_count = 0
        
        # 异常信息
        self.errors = []
        self.warnings = []
    
    def add_error(self, error, score_penalty=20):
        """添加错误并扣分"""
        self.errors.append(error)
        self.score = max(0, self.score - score_penalty)
    
    def add_warning(self, warning, score_penalty=10):
        """添加警告并扣分"""
        self.warnings.append(warning)
        self.score = max(0, self.score - score_penalty)
    
    @property
    def is_abnormal(self):
        """是否存在异常"""
        return len(self.errors) > 0 or len(self.warnings) > 0
    
    @property
    def risk_level(self):
        """风险等级"""
        if self.score >= 90:
            return "健康"
        elif self.score >= 70:
            return "低风险"
        elif self.score >= 50:
            return "中风险"
        else:
            return "高风险"
    
    @property
    def risk_summary(self):
        """风险摘要（用于高风险提示）"""
        reasons = []
        for error in self.errors:
            if "CPU" in error:
                reasons.append("CPU过载")
            elif "内存" in error:
                reasons.append("内存不足")
            elif "磁盘" in error:
                reasons.append("磁盘空间不足")
            elif "僵尸" in error:
                reasons.append("存在僵尸进程")
            elif "超时" in error or "连接" in error:
                reasons.append("连接失败")
            elif "认证" in error:
                reasons.append("认证失败")
            elif "SSH" in error:
                reasons.append("SSH异常")
            else:
                reasons.append("系统异常")
        # 去重
        return list(dict.fromkeys(reasons))
    
    @property
    def risk_color(self):
        """风险等级对应颜色"""
        if self.score >= 90:
            return "#28a745"  # 绿色
        elif self.score >= 70:
            return "#ffc107"  # 黄色
        elif self.score >= 50:
            return "#fd7e14"  # 橙色
        else:
            return "#dc3545"  # 红色


class ServerInspector(object):
    """服务器巡检器"""
    
    def __init__(self, timeout=None):
        if timeout is None:
            timeout = THRESHOLDS["ssh_timeout"]
        self.timeout = timeout
    
    def connect(self, config):
        """建立SSH连接"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        connect_kwargs = {
            "hostname": config.host,
            "port": config.port,
            "username": config.username,
            "timeout": self.timeout,
            "banner_timeout": self.timeout,
            "auth_timeout": self.timeout,
        }
        
        if config.key_file:
            connect_kwargs["key_filename"] = config.key_file
        elif config.password:
            connect_kwargs["password"] = config.password
        
        client.connect(**connect_kwargs)
        return client
    
    def execute_command(self, client, command):
        """执行远程命令"""
        stdin, stdout, stderr = client.exec_command(command, timeout=30)
        return stdout.read().decode("utf-8", errors="ignore").strip()
    
    def check_cpu(self, client, result):
        """检查CPU使用率"""
        try:
            # 使用top命令获取CPU使用率（采样1秒）
            output = self.execute_command(
                client,
                "top -bn2 -d1 | grep 'Cpu(s)' | tail -1 | awk '{print 100-$8}'"
            )
            if output:
                cpu_percent = float(output)
                result.cpu_percent = cpu_percent
                
                if cpu_percent > THRESHOLDS["cpu_percent"]:
                    result.add_error(
                        "CPU使用率过高: {0:.1f}% (阈值: {1}%)".format(
                            cpu_percent, THRESHOLDS['cpu_percent']
                        ),
                        score_penalty=15
                    )
        except Exception as e:
            result.add_warning("CPU检查失败: {0}".format(str(e)), score_penalty=5)
    
    def check_memory(self, client, result):
        """检查内存使用率"""
        try:
            output = self.execute_command(
                client,
                "free | grep Mem | awk '{print ($3/$2)*100}'"
            )
            if output:
                memory_percent = float(output)
                result.memory_percent = memory_percent
                
                if memory_percent > THRESHOLDS["memory_percent"]:
                    result.add_error(
                        "内存使用率过高: {0:.1f}% (阈值: {1}%)".format(
                            memory_percent, THRESHOLDS['memory_percent']
                        ),
                        score_penalty=20
                    )
        except Exception as e:
            result.add_warning("内存检查失败: {0}".format(str(e)), score_penalty=5)
    
    def check_disk(self, client, result):
        """检查磁盘使用率"""
        try:
            output = self.execute_command(
                client,
                "df -h | grep -E '^/dev' | awk '{print $6\"|\"$5}'"
            )
            if output:
                result.disk_usage = {}
                for line in output.split("\n"):
                    if "|" in line:
                        parts = line.split("|")
                        mount_point = parts[0]
                        usage_str = parts[1].replace("%", "")
                        try:
                            usage = float(usage_str)
                            result.disk_usage[mount_point] = usage
                            
                            if usage > THRESHOLDS["disk_percent"]:
                                result.add_error(
                                    "磁盘 {0} 使用率过高: {1:.1f}% (阈值: {2}%)".format(
                                        mount_point, usage, THRESHOLDS['disk_percent']
                                    ),
                                    score_penalty=15
                                )
                        except ValueError:
                            pass
        except Exception as e:
            result.add_warning("磁盘检查失败: {0}".format(str(e)), score_penalty=5)
    
    def check_zombie_processes(self, client, result):
        """检查僵尸进程"""
        try:
            output = self.execute_command(
                client,
                "ps aux | awk '$8 ~ /Z/ {print}' | wc -l"
            )
            if output:
                zombie_count = int(output)
                result.zombie_count = zombie_count
                
                if zombie_count > 0:
                    # 获取僵尸进程详情
                    zombie_details = self.execute_command(
                        client,
                        "ps aux | awk '$8 ~ /Z/ {print $2, $11}' | head -5"
                    )
                    error_msg = "存在 {0} 个僵尸进程".format(zombie_count)
                    if zombie_details:
                        error_msg += " (PID: {0})".format(zombie_details.replace('\n', ', '))
                    result.add_error(error_msg, score_penalty=10)
        except Exception as e:
            result.add_warning("僵尸进程检查失败: {0}".format(str(e)), score_penalty=5)
    
    def inspect(self, config):
        """执行巡检"""
        result = InspectionResult(host=config.host)
        client = None
        
        try:
            # 建立SSH连接
            client = self.connect(config)
            
            # 执行各项检查
            self.check_cpu(client, result)
            self.check_memory(client, result)
            self.check_disk(client, result)
            self.check_zombie_processes(client, result)
            
        except paramiko.AuthenticationException:
            result.success = False
            result.add_error("SSH认证失败", score_penalty=100)
        except paramiko.SSHException as e:
            result.success = False
            result.add_error("SSH连接异常: {0}".format(str(e)), score_penalty=100)
        except Exception as e:
            result.success = False
            error_name = type(e).__name__
            if "timeout" in error_name.lower() or "Timeout" in str(e):
                result.add_error("连接超时 (超过{0}秒)".format(self.timeout), score_penalty=100)
            else:
                result.add_error("巡检失败: {0}".format(str(e)), score_penalty=100)
        finally:
            if client:
                client.close()
        
        return result


class HTMLReportGenerator(object):
    """HTML报告生成器"""
    
    @staticmethod
    def generate(results, title="服务器巡检报告"):
        """生成HTML报告"""
        
        # 统计信息
        total = len(results)
        abnormal = sum(1 for r in results if r.is_abnormal)
        failed = sum(1 for r in results if not r.success)
        high_risk = sum(1 for r in results if r.score < 50)
        avg_score = sum(r.score for r in results) / total if total > 0 else 0
        
        html = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            padding: 30px;
            color: #e0e0e0;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding: 30px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .header h1 {{
            font-size: 2.5em;
            color: #fff;
            margin-bottom: 10px;
            text-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }}
        .header .subtitle {{
            color: #a0a0a0;
            font-size: 1.1em;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .summary-card {{
            background: rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        .summary-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }}
        .summary-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .summary-card .label {{
            color: #a0a0a0;
            font-size: 0.95em;
        }}
        .summary-card.total .number {{ color: #4ecdc4; }}
        .summary-card.abnormal .number {{ color: #ff6b6b; }}
        .summary-card.high-risk .number {{ color: #dc3545; }}
        .summary-card.failed .number {{ color: #feca57; }}
        .summary-card.score .number {{ color: #48dbfb; }}
        
        .section-title {{
            font-size: 1.5em;
            color: #fff;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid rgba(255, 255, 255, 0.1);
        }}
        
        .server-list {{
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}
        .server-card {{
            background: rgba(255, 255, 255, 0.06);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: box-shadow 0.3s ease;
        }}
        .server-card:hover {{
            box-shadow: 0 5px 20px rgba(0,0,0,0.3);
        }}
        .server-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 25px;
            background: rgba(0, 0, 0, 0.2);
        }}
        .server-host {{
            font-size: 1.3em;
            font-weight: 600;
            color: #fff;
        }}
        .server-score {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        .score-badge {{
            font-size: 1.8em;
            font-weight: bold;
        }}
        .risk-badge {{
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        .server-body {{
            padding: 25px;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .metric {{
            background: rgba(0, 0, 0, 0.2);
            padding: 15px;
            border-radius: 8px;
        }}
        .metric-label {{
            color: #a0a0a0;
            font-size: 0.85em;
            margin-bottom: 5px;
        }}
        .metric-value {{
            font-size: 1.4em;
            font-weight: 600;
            color: #fff;
        }}
        .errors {{
            background: rgba(220, 53, 69, 0.15);
            border-left: 4px solid #dc3545;
            padding: 15px 20px;
            border-radius: 0 8px 8px 0;
            margin-top: 15px;
        }}
        .errors-title {{
            color: #ff6b6b;
            font-weight: 600;
            margin-bottom: 10px;
            font-size: 0.95em;
        }}
        .error-item {{
            padding: 8px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            color: #f0a0a0;
        }}
        .error-item:last-child {{
            border-bottom: none;
        }}
        .warnings {{
            background: rgba(255, 193, 7, 0.15);
            border-left: 4px solid #ffc107;
            padding: 15px 20px;
            border-radius: 0 8px 8px 0;
            margin-top: 15px;
        }}
        .warnings-title {{
            color: #feca57;
            font-weight: 600;
            margin-bottom: 10px;
            font-size: 0.95em;
        }}
        .warning-item {{
            padding: 8px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            color: #f0d090;
        }}
        .warning-item:last-child {{
            border-bottom: none;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #707070;
            font-size: 0.9em;
        }}
        .no-issues {{
            color: #4ecdc4;
            padding: 15px;
            text-align: center;
            font-size: 1.1em;
        }}
        .high-risk-alert {{
            background: linear-gradient(135deg, rgba(220, 53, 69, 0.25) 0%, rgba(220, 53, 69, 0.15) 100%);
            border: 2px solid #dc3545;
            border-radius: 10px;
            padding: 18px 22px;
            margin-bottom: 20px;
            animation: pulse-alert 2s ease-in-out infinite;
        }}
        @keyframes pulse-alert {{
            0%, 100% {{ box-shadow: 0 0 5px rgba(220, 53, 69, 0.3); }}
            50% {{ box-shadow: 0 0 20px rgba(220, 53, 69, 0.6); }}
        }}
        .high-risk-title {{
            color: #ff6b6b;
            font-size: 1.1em;
            font-weight: bold;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .high-risk-reasons {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 10px;
        }}
        .risk-reason-tag {{
            background: rgba(220, 53, 69, 0.3);
            color: #ff8a8a;
            padding: 6px 14px;
            border-radius: 15px;
            font-size: 0.9em;
            font-weight: 500;
            border: 1px solid rgba(220, 53, 69, 0.5);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>&#128421; {title}</h1>
            <div class="subtitle">生成时间: {gen_time}</div>
        </div>
        
        <div class="summary">
            <div class="summary-card total">
                <div class="number">{total}</div>
                <div class="label">服务器总数</div>
            </div>
            <div class="summary-card abnormal">
                <div class="number">{abnormal}</div>
                <div class="label">异常服务器</div>
            </div>
            <div class="summary-card high-risk">
                <div class="number">{high_risk}</div>
                <div class="label">高风险服务器</div>
            </div>
            <div class="summary-card failed">
                <div class="number">{failed}</div>
                <div class="label">连接失败</div>
            </div>
            <div class="summary-card score">
                <div class="number">{avg_score:.0f}</div>
                <div class="label">平均健康分</div>
            </div>
        </div>
        
        <h2 class="section-title">&#128202; 巡检详情</h2>
        <div class="server-list">
""".format(
            title=title,
            gen_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total=total,
            abnormal=abnormal,
            high_risk=high_risk,
            failed=failed,
            avg_score=avg_score
        )
        
        # 按分数排序，异常的排前面
        sorted_results = sorted(results, key=lambda x: (x.success, x.score))
        
        for r in sorted_results:
            cpu_display = "{0:.1f}%".format(r.cpu_percent) if r.cpu_percent is not None else "N/A"
            mem_display = "{0:.1f}%".format(r.memory_percent) if r.memory_percent is not None else "N/A"
            
            html += """
            <div class="server-card">
                <div class="server-header">
                    <span class="server-host">&#128421; {host}</span>
                    <div class="server-score">
                        <span class="score-badge" style="color: {risk_color}">{score}分</span>
                        <span class="risk-badge" style="background: {risk_color}; color: #fff">{risk_level}</span>
                    </div>
                </div>
                <div class="server-body">
""".format(
                host=r.host,
                risk_color=r.risk_color,
                score=r.score,
                risk_level=r.risk_level
            )
            
            # 高风险服务器显示风险原因摘要
            if r.score < 50 and r.risk_summary:
                reason_tags = "".join(
                    '<span class="risk-reason-tag">{0}</span>'.format(reason) 
                    for reason in r.risk_summary
                )
                html += """
                    <div class="high-risk-alert">
                        <div class="high-risk-title">&#9888; 高风险警告</div>
                        <div>该服务器存在严重风险，需要立即关注！</div>
                        <div class="high-risk-reasons">{reasons}</div>
                    </div>
""".format(reasons=reason_tags)
            
            html += """
                    <div class="metrics">
                        <div class="metric">
                            <div class="metric-label">CPU使用率</div>
                            <div class="metric-value">{cpu}</div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">内存使用率</div>
                            <div class="metric-value">{mem}</div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">僵尸进程</div>
                            <div class="metric-value">{zombie}</div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">巡检时间</div>
                            <div class="metric-value" style="font-size: 0.9em">{timestamp}</div>
                        </div>
                    </div>
""".format(
                cpu=cpu_display,
                mem=mem_display,
                zombie=r.zombie_count,
                timestamp=r.timestamp
            )
            
            # 磁盘使用情况
            if r.disk_usage:
                html += '<div class="metrics">'
                for mount, usage in r.disk_usage.items():
                    color = "#ff6b6b" if usage > THRESHOLDS["disk_percent"] else "#4ecdc4"
                    html += """
                        <div class="metric">
                            <div class="metric-label">磁盘 {mount}</div>
                            <div class="metric-value" style="color: {color}">{usage:.1f}%</div>
                        </div>
""".format(mount=mount, color=color, usage=usage)
                html += '</div>'
            
            # 错误信息
            if r.errors:
                html += """
                    <div class="errors">
                        <div class="errors-title">&#10060; 异常项目</div>
"""
                for error in r.errors:
                    html += '<div class="error-item">&#8226; {0}</div>'.format(error)
                html += '</div>'
            
            # 警告信息
            if r.warnings:
                html += """
                    <div class="warnings">
                        <div class="warnings-title">&#9888; 警告项目</div>
"""
                for warning in r.warnings:
                    html += '<div class="warning-item">&#8226; {0}</div>'.format(warning)
                html += '</div>'
            
            if not r.errors and not r.warnings:
                html += '<div class="no-issues">&#9989; 所有指标正常</div>'
            
            html += """
                </div>
            </div>
"""
        
        html += """
        </div>
        
        <div class="footer">
            <p>服务器自动化巡检系统 | Generated by Server Inspector</p>
        </div>
    </div>
</body>
</html>
"""
        return html


class EmailSender(object):
    """邮件发送器"""
    
    def __init__(self, smtp_host, smtp_port, username, password, use_ssl=True):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
    
    def send(self, to_addrs, subject, html_content, from_name="服务器巡检系统"):
        """发送HTML邮件"""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = "{0} <{1}>".format(from_name, self.username)
        msg["To"] = ", ".join(to_addrs)
        
        html_part = MIMEText(html_content, "html", "utf-8")
        msg.attach(html_part)
        
        if self.use_ssl:
            server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port)
        else:
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.starttls()
        
        try:
            server.login(self.username, self.password)
            server.sendmail(self.username, to_addrs, msg.as_string())
            print("✅ 邮件发送成功: {0}".format(", ".join(to_addrs)))
        finally:
            server.quit()


def load_servers_from_file(file_path):
    """从JSON文件加载服务器配置"""
    with open(file_path, "r") as f:
        data = json.load(f)
    
    servers = []
    for item in data.get("servers", []):
        servers.append(ServerConfig(
            host=item["host"],
            port=item.get("port", 22),
            username=item.get("username", "root"),
            password=item.get("password"),
            key_file=item.get("key_file"),
        ))
    return servers


def run_inspection(servers, max_workers=10):
    """并发执行巡检"""
    inspector = ServerInspector()
    results = []
    
    print("\n🚀 开始巡检 {0} 台服务器 (并发数: {1})".format(len(servers), max_workers))
    print("-" * 50)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_server = dict(
            (executor.submit(inspector.inspect, server), server)
            for server in servers
        )
        
        for future in as_completed(future_to_server):
            server = future_to_server[future]
            try:
                result = future.result()
                results.append(result)
                
                status = "✅" if not result.is_abnormal else "❌"
                output_msg = "{0} {1}: 评分 {2}, {3}".format(
                    status, server.host, result.score, result.risk_level
                )
                # 高风险显示具体原因
                if result.score < 50 and result.risk_summary:
                    output_msg += " [原因: {0}]".format(", ".join(result.risk_summary))
                print(output_msg)
                
            except Exception as e:
                # 即使future.result()出错也要记录
                result = InspectionResult(host=server.host)
                result.success = False
                result.add_error("执行异常: {0}".format(str(e)), score_penalty=100)
                results.append(result)
                print("❌ {0}: 执行异常 - {1}".format(server.host, str(e)))
    
    print("-" * 50)
    abnormal_count = sum(1 for r in results if r.is_abnormal)
    high_risk_count = sum(1 for r in results if r.score < 50)
    print("✅ 巡检完成: 共 {0} 台, 异常 {1} 台, 高风险 {2} 台".format(
        len(results), abnormal_count, high_risk_count
    ))
    
    # 高风险服务器汇总
    if high_risk_count > 0:
        print("\n⚠️  高风险服务器汇总:")
        for r in results:
            if r.score < 50:
                reasons = ", ".join(r.risk_summary) if r.risk_summary else "未知"
                print("   • {0} (评分: {1}) - 原因: {2}".format(r.host, r.score, reasons))
    
    return results


def main():
    parser = argparse.ArgumentParser(description="服务器自动化巡检脚本")
    parser.add_argument("-c", "--config", required=True, help="服务器配置文件路径 (JSON格式)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="并发数 (默认: 10)")
    parser.add_argument("-o", "--output", help="HTML报告输出路径")
    parser.add_argument("--smtp-host", help="SMTP服务器地址")
    parser.add_argument("--smtp-port", type=int, default=465, help="SMTP端口 (默认: 465)")
    parser.add_argument("--smtp-user", help="SMTP用户名")
    parser.add_argument("--smtp-pass", help="SMTP密码")
    parser.add_argument("--smtp-ssl", action="store_true", default=True, help="使用SSL (默认: True)")
    parser.add_argument("--mail-to", nargs="+", help="收件人邮箱列表")
    parser.add_argument("--mail-subject", default="服务器巡检报告", help="邮件主题")
    
    args = parser.parse_args()
    
    # 加载服务器配置
    servers = load_servers_from_file(args.config)
    if not servers:
        print("❌ 未找到服务器配置")
        return
    
    # 执行巡检
    results = run_inspection(servers, max_workers=args.workers)
    
    # 生成HTML报告
    html_report = HTMLReportGenerator.generate(results, title=args.mail_subject)
    
    # 保存报告到文件
    if args.output:
        with open(args.output, "w") as f:
            f.write(html_report.encode("utf-8"))
        print("📄 报告已保存: {0}".format(args.output))
    
    # 发送邮件
    if args.smtp_host and args.smtp_user and args.smtp_pass and args.mail_to:
        try:
            sender = EmailSender(
                smtp_host=args.smtp_host,
                smtp_port=args.smtp_port,
                username=args.smtp_user,
                password=args.smtp_pass,
                use_ssl=args.smtp_ssl,
            )
            sender.send(
                to_addrs=args.mail_to,
                subject="{0} - {1}".format(
                    args.mail_subject,
                    datetime.now().strftime('%Y-%m-%d')
                ),
                html_content=html_report,
            )
        except Exception as e:
            print("❌ 邮件发送失败: {0}".format(str(e)))
    elif args.mail_to:
        print("⚠️  需要提供SMTP配置才能发送邮件")


if __name__ == "__main__":
    main()
