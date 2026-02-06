#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
服务器自动化巡检脚本 (Python 2.7 兼容版本)
功能：对指定服务器进行SSH连接，检查主机资源和进程状态，自动标记异常主机，并通过邮件发送HTML报告
"""

from __future__ import print_function, unicode_literals

import os
import sys
import signal
import smtplib
import argparse
import json
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
import paramiko

# 全局停止标志
_shutdown_event = threading.Event()


def signal_handler(signum, frame):
    """信号处理函数"""
    print("\n\n⚠️  接收到中断信号 (Ctrl+C)，正在停止巡检...")
    _shutdown_event.set()


# 注册信号处理
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


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
                # 未分类的错误，显示具体报错信息
                # 截取错误信息，避免过长
                error_msg = error
                if len(error_msg) > 50:
                    error_msg = error_msg[:47] + "..."
                reasons.append(error_msg)
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
            # 展开 ~ 为实际用户主目录路径
            key_path = os.path.expanduser(config.key_file)
            connect_kwargs["key_filename"] = key_path
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
            background: #0d1117;
            min-height: 100vh;
            padding: 30px;
            color: #c9d1d9;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding: 40px 30px;
            background: linear-gradient(135deg, #161b22 0%, #21262d 100%);
            border-radius: 16px;
            border: 1px solid #30363d;
        }}
        .header h1 {{
            font-size: 2.2em;
            color: #58a6ff;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }}
        .header .subtitle {{
            color: #8b949e;
            font-size: 1em;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 40px;
        }}
        .summary-card {{
            background: #161b22;
            border-radius: 12px;
            padding: 24px 20px;
            text-align: center;
            border: 1px solid #30363d;
        }}
        .summary-card .number {{
            font-size: 2.8em;
            font-weight: 700;
            margin-bottom: 8px;
            line-height: 1;
        }}
        .summary-card .label {{
            color: #8b949e;
            font-size: 0.9em;
            font-weight: 500;
        }}
        .summary-card.total .number {{ color: #58a6ff; }}
        .summary-card.abnormal .number {{ color: #f97583; }}
        .summary-card.high-risk .number {{ color: #ff7b72; }}
        .summary-card.failed .number {{ color: #d29922; }}
        .summary-card.score .number {{ color: #56d364; }}
        
        .section-title {{
            font-size: 1.4em;
            color: #c9d1d9;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 1px solid #30363d;
            font-weight: 600;
        }}
        
        .server-list {{
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}
        .server-card {{
            background: #161b22;
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid #30363d;
        }}
        .server-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 18px 24px;
            background: #21262d;
            border-bottom: 1px solid #30363d;
        }}
        .server-host {{
            font-size: 1.15em;
            font-weight: 600;
            color: #c9d1d9;
        }}
        .server-score {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .score-badge {{
            font-size: 1.6em;
            font-weight: 700;
        }}
        .risk-badge {{
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            letter-spacing: 0.3px;
        }}
        .server-body {{
            padding: 24px;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }}
        .metric {{
            background: #0d1117;
            padding: 16px;
            border-radius: 10px;
            border: 1px solid #21262d;
        }}
        .metric-label {{
            color: #8b949e;
            font-size: 0.8em;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .metric-value {{
            font-size: 1.3em;
            font-weight: 600;
            color: #c9d1d9;
        }}
        .errors {{
            background: #21262d;
            border-left: 4px solid #f85149;
            padding: 16px 20px;
            border-radius: 0 10px 10px 0;
            margin-top: 16px;
        }}
        .errors-title {{
            color: #f85149;
            font-weight: 600;
            margin-bottom: 12px;
            font-size: 0.95em;
        }}
        .error-item {{
            padding: 8px 0;
            border-bottom: 1px solid #30363d;
            color: #f97583;
            font-size: 0.9em;
        }}
        .error-item:last-child {{
            border-bottom: none;
        }}
        .warnings {{
            background: #21262d;
            border-left: 4px solid #d29922;
            padding: 16px 20px;
            border-radius: 0 10px 10px 0;
            margin-top: 16px;
        }}
        .warnings-title {{
            color: #d29922;
            font-weight: 600;
            margin-bottom: 12px;
            font-size: 0.95em;
        }}
        .warning-item {{
            padding: 8px 0;
            border-bottom: 1px solid #30363d;
            color: #e3b341;
            font-size: 0.9em;
        }}
        .warning-item:last-child {{
            border-bottom: none;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #484f58;
            font-size: 0.85em;
        }}
        .no-issues {{
            color: #56d364;
            padding: 20px;
            text-align: center;
            font-size: 1em;
            background: #0d1117;
            border-radius: 10px;
            border: 1px solid #238636;
        }}
        .high-risk-alert {{
            background: #3d1418;
            border: 2px solid #f85149;
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 20px;
        }}
        .high-risk-title {{
            color: #ff7b72;
            font-size: 1.1em;
            font-weight: 700;
            margin-bottom: 8px;
        }}
        .high-risk-desc {{
            color: #f97583;
            font-size: 0.95em;
            margin-bottom: 14px;
        }}
        .risk-reasons {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .risk-reason-tag {{
            background: #f85149;
            color: #ffffff;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        .deduction-alert {{
            background: #2d2305;
            border: 2px solid #d29922;
            border-radius: 12px;
            padding: 18px 22px;
            margin-bottom: 20px;
        }}
        .deduction-title {{
            color: #e3b341;
            font-size: 1em;
            font-weight: 700;
            margin-bottom: 12px;
        }}
        .deduction-alert .risk-reason-tag {{
            background: #d29922;
            color: #0d1117;
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
            
            # 显示减分原因摘要
            if r.score < 100 and r.risk_summary:
                reason_tags = "".join(
                    '<span class="risk-reason-tag">{0}</span>'.format(reason) 
                    for reason in r.risk_summary
                )
                if r.score < 50:
                    # 高风险
                    html += """
                    <div class="high-risk-alert">
                        <div class="high-risk-title">&#9888; 高风险警告</div>
                        <div class="high-risk-desc">该服务器存在严重风险，需要立即关注！</div>
                        <div class="risk-reasons">{reasons}</div>
                    </div>
""".format(reasons=reason_tags)
                else:
                    # 中低风险，显示减分原因
                    html += """
                    <div class="deduction-alert">
                        <div class="deduction-title">&#128270; 减分原因</div>
                        <div class="risk-reasons">{reasons}</div>
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
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = formataddr((str(Header(from_name, "utf-8")), self.username))
        msg["To"] = ", ".join(to_addrs)
        
        html_part = MIMEText(html_content, "html", "utf-8")
        msg.attach(html_part)
        
        server = None
        try:
            # 根据端口自动选择连接方式
            # 465: 直接 SSL 连接 (SMTP_SSL)
            # 587/25: 先普通连接再 STARTTLS
            if self.smtp_port == 465:
                # 直接 SSL 连接
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port)
            elif self.smtp_port == 587 or self.smtp_port == 25:
                # STARTTLS 模式
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                server.ehlo()
                server.starttls()
                server.ehlo()
            else:
                # 其他端口根据 use_ssl 参数决定
                if self.use_ssl:
                    server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port)
                else:
                    server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
            
            server.login(self.username, self.password)
            server.sendmail(self.username, to_addrs, msg.as_string())
            print("✅ 邮件发送成功: {0}".format(", ".join(to_addrs)))
        finally:
            if server:
                server.quit()


class EmailConfig(object):
    """邮件配置"""
    
    def __init__(self, smtp_host=None, smtp_port=465, smtp_user=None, 
                 smtp_pass=None, smtp_ssl=True, mail_to=None, mail_subject="服务器巡检报告"):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.smtp_ssl = smtp_ssl
        self.mail_to = mail_to if mail_to else []
        self.mail_subject = mail_subject
    
    @property
    def is_valid(self):
        """检查邮件配置是否完整"""
        return all([self.smtp_host, self.smtp_user, self.smtp_pass, self.mail_to])


def load_config_from_file(file_path):
    """从JSON文件加载配置（服务器列表和邮件配置）"""
    with open(file_path, "r") as f:
        data = json.load(f)
    
    # 加载服务器配置
    servers = []
    for item in data.get("servers", []):
        servers.append(ServerConfig(
            host=item["host"],
            port=item.get("port", 22),
            username=item.get("username", "root"),
            password=item.get("password"),
            key_file=item.get("key_file"),
        ))
    
    # 加载邮件配置
    email_config = None
    email_data = data.get("email")
    if email_data:
        mail_to = email_data.get("mail_to", [])
        # 兼容字符串和列表格式
        if isinstance(mail_to, str):
            mail_to = [mail_to]
        
        email_config = EmailConfig(
            smtp_host=email_data.get("smtp_host"),
            smtp_port=email_data.get("smtp_port", 465),
            smtp_user=email_data.get("smtp_user"),
            smtp_pass=email_data.get("smtp_pass"),
            smtp_ssl=email_data.get("smtp_ssl", True),
            mail_to=mail_to,
            mail_subject=email_data.get("mail_subject", "服务器巡检报告"),
        )
    
    return servers, email_config


def run_inspection(servers, max_workers=10):
    """并发执行巡检"""
    inspector = ServerInspector()
    results = []
    interrupted = False
    
    print("\n🚀 开始巡检 {0} 台服务器 (并发数: {1})".format(len(servers), max_workers))
    print("   (按 Ctrl+C 可中断巡检)")
    print("-" * 50)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_server = dict(
            (executor.submit(inspector.inspect, server), server)
            for server in servers
        )
        
        try:
            for future in as_completed(future_to_server):
                # 检查是否收到中断信号
                if _shutdown_event.is_set():
                    interrupted = True
                    # 取消尚未开始的任务
                    for f in future_to_server:
                        f.cancel()
                    break
                
                server = future_to_server[future]
                try:
                    result = future.result(timeout=1)
                    results.append(result)
                    
                    status = "✅" if not result.is_abnormal else "❌"
                    output_msg = "{0} {1}: 评分 {2}, {3}".format(
                        status, server.host, result.score, result.risk_level
                    )
                    # 低于100分显示减分原因
                    if result.score < 100 and result.risk_summary:
                        output_msg += " [原因: {0}]".format(", ".join(result.risk_summary))
                    print(output_msg)
                    
                except Exception as e:
                    if _shutdown_event.is_set():
                        interrupted = True
                        break
                    # 即使future.result()出错也要记录
                    result = InspectionResult(host=server.host)
                    result.success = False
                    result.add_error("执行异常: {0}".format(str(e)), score_penalty=100)
                    results.append(result)
                    print("❌ {0}: 执行异常 - {1}".format(server.host, str(e)))
        except KeyboardInterrupt:
            interrupted = True
            print("\n⚠️  用户中断，正在停止...")
    
    print("-" * 50)
    
    if interrupted:
        print("⚠️  巡检被中断: 已完成 {0}/{1} 台".format(len(results), len(servers)))
    else:
        abnormal_count = sum(1 for r in results if r.is_abnormal)
        high_risk_count = sum(1 for r in results if r.score < 50)
        print("✅ 巡检完成: 共 {0} 台, 异常 {1} 台, 高风险 {2} 台".format(
            len(results), abnormal_count, high_risk_count
        ))
    
    # 异常服务器汇总（低于100分）
    abnormal_results = [r for r in results if r.score < 100]
    if abnormal_results:
        # 按评分排序，分数低的在前
        abnormal_results.sort(key=lambda x: x.score)
        print("\n📋 减分服务器汇总:")
        for r in abnormal_results:
            reasons = ", ".join(r.risk_summary) if r.risk_summary else "未知"
            level_icon = "🔴" if r.score < 50 else "🟠" if r.score < 70 else "🟡"
            print("   {0} {1} (评分: {2}, {3}) - 原因: {4}".format(
                level_icon, r.host, r.score, r.risk_level, reasons
            ))
    
    return results, interrupted


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
    
    # 加载配置文件（服务器列表和邮件配置）
    try:
        servers, file_email_config = load_config_from_file(args.config)
    except Exception as e:
        print("❌ 加载配置文件失败: {0}".format(str(e)))
        return
    
    if not servers:
        print("❌ 未找到服务器配置")
        return
    
    # 合并邮件配置（命令行参数优先级高于配置文件）
    email_config = file_email_config if file_email_config else EmailConfig()
    if args.smtp_host:
        email_config.smtp_host = args.smtp_host
    if args.smtp_port != 465:  # 非默认值时覆盖
        email_config.smtp_port = args.smtp_port
    if args.smtp_user:
        email_config.smtp_user = args.smtp_user
    if args.smtp_pass:
        email_config.smtp_pass = args.smtp_pass
    if args.mail_to:
        email_config.mail_to = args.mail_to
    if args.mail_subject != "服务器巡检报告":  # 非默认值时覆盖
        email_config.mail_subject = args.mail_subject
    
    # 执行巡检
    results, interrupted = run_inspection(servers, max_workers=args.workers)
    
    # 如果没有任何结果，直接退出
    if not results:
        print("⚠️  没有巡检结果")
        return
    
    # 生成HTML报告
    html_report = HTMLReportGenerator.generate(results, title=email_config.mail_subject)
    
    # 保存报告到文件
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(html_report.encode("utf-8"))
            print("📄 报告已保存: {0}".format(args.output))
        except Exception as e:
            print("❌ 保存报告失败: {0}".format(str(e)))
    
    # 发送邮件（即使被中断，如果有结果也可以发送部分报告）
    if email_config.is_valid:
        if interrupted:
            print("\n📧 发送部分巡检结果邮件 (已完成 {0}/{1} 台)".format(
                len(results), len(servers)
            ))
        try:
            subject_suffix = " [部分结果]" if interrupted else ""
            sender = EmailSender(
                smtp_host=email_config.smtp_host,
                smtp_port=email_config.smtp_port,
                username=email_config.smtp_user,
                password=email_config.smtp_pass,
                use_ssl=email_config.smtp_ssl,
            )
            sender.send(
                to_addrs=email_config.mail_to,
                subject="{0} - {1}{2}".format(
                    email_config.mail_subject,
                    datetime.now().strftime('%Y-%m-%d'),
                    subject_suffix
                ),
                html_content=html_report,
            )
        except Exception as e:
            print("❌ 邮件发送失败: {0}".format(str(e)))
    elif email_config.mail_to:
        print("⚠️  邮件配置不完整，需要提供 smtp_host, smtp_user, smtp_pass")
    
    # 返回退出码
    if interrupted:
        sys.exit(130)  # 标准的 Ctrl+C 退出码


if __name__ == "__main__":
    main()
