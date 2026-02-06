#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
服务器自动化巡检脚本
功能：对指定服务器进行SSH连接，检查主机资源和进程状态，自动标记异常主机，并通过邮件发送HTML报告
"""

import os
import smtplib
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass, field
from typing import Optional
import paramiko


# ==================== 配置常量 ====================
THRESHOLDS = {
    "disk_percent": 85,      # 磁盘使用率阈值 %
    "memory_percent": 95,    # 内存使用率阈值 %
    "cpu_percent": 80,       # CPU使用率阈值 %
    "ssh_timeout": 60,       # SSH连接超时时间（秒）
}


@dataclass
class ServerConfig:
    """服务器配置"""
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    key_file: Optional[str] = None


@dataclass
class InspectionResult:
    """巡检结果"""
    host: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    success: bool = True
    score: int = 100  # 健康评分，满分100
    
    # 资源使用情况
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    disk_usage: Optional[dict] = None  # {挂载点: 使用率}
    zombie_count: int = 0
    
    # 异常信息
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    
    def add_error(self, error: str, score_penalty: int = 20):
        """添加错误并扣分"""
        self.errors.append(error)
        self.score = max(0, self.score - score_penalty)
    
    def add_warning(self, warning: str, score_penalty: int = 10):
        """添加警告并扣分"""
        self.warnings.append(warning)
        self.score = max(0, self.score - score_penalty)
    
    @property
    def is_abnormal(self) -> bool:
        """是否存在异常"""
        return len(self.errors) > 0 or len(self.warnings) > 0
    
    @property
    def risk_level(self) -> str:
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
    def risk_color(self) -> str:
        """风险等级对应颜色"""
        if self.score >= 90:
            return "#28a745"  # 绿色
        elif self.score >= 70:
            return "#ffc107"  # 黄色
        elif self.score >= 50:
            return "#fd7e14"  # 橙色
        else:
            return "#dc3545"  # 红色


class ServerInspector:
    """服务器巡检器"""
    
    def __init__(self, timeout: int = THRESHOLDS["ssh_timeout"]):
        self.timeout = timeout
    
    def connect(self, config: ServerConfig) -> paramiko.SSHClient:
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
    
    def execute_command(self, client: paramiko.SSHClient, command: str) -> str:
        """执行远程命令"""
        stdin, stdout, stderr = client.exec_command(command, timeout=30)
        return stdout.read().decode("utf-8", errors="ignore").strip()
    
    def check_cpu(self, client: paramiko.SSHClient, result: InspectionResult):
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
                        f"CPU使用率过高: {cpu_percent:.1f}% (阈值: {THRESHOLDS['cpu_percent']}%)",
                        score_penalty=15
                    )
        except Exception as e:
            result.add_warning(f"CPU检查失败: {str(e)}", score_penalty=5)
    
    def check_memory(self, client: paramiko.SSHClient, result: InspectionResult):
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
                        f"内存使用率过高: {memory_percent:.1f}% (阈值: {THRESHOLDS['memory_percent']}%)",
                        score_penalty=20
                    )
        except Exception as e:
            result.add_warning(f"内存检查失败: {str(e)}", score_penalty=5)
    
    def check_disk(self, client: paramiko.SSHClient, result: InspectionResult):
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
                                    f"磁盘 {mount_point} 使用率过高: {usage:.1f}% (阈值: {THRESHOLDS['disk_percent']}%)",
                                    score_penalty=15
                                )
                        except ValueError:
                            pass
        except Exception as e:
            result.add_warning(f"磁盘检查失败: {str(e)}", score_penalty=5)
    
    def check_zombie_processes(self, client: paramiko.SSHClient, result: InspectionResult):
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
                    result.add_error(
                        f"存在 {zombie_count} 个僵尸进程" + 
                        (f" (PID: {zombie_details.replace(chr(10), ', ')})" if zombie_details else ""),
                        score_penalty=10
                    )
        except Exception as e:
            result.add_warning(f"僵尸进程检查失败: {str(e)}", score_penalty=5)
    
    def inspect(self, config: ServerConfig) -> InspectionResult:
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
            result.add_error(f"SSH连接异常: {str(e)}", score_penalty=100)
        except TimeoutError:
            result.success = False
            result.add_error(f"连接超时 (超过{self.timeout}秒)", score_penalty=100)
        except Exception as e:
            result.success = False
            result.add_error(f"巡检失败: {str(e)}", score_penalty=100)
        finally:
            if client:
                client.close()
        
        return result


class HTMLReportGenerator:
    """HTML报告生成器"""
    
    @staticmethod
    def generate(results: list[InspectionResult], title: str = "服务器巡检报告") -> str:
        """生成HTML报告"""
        
        # 统计信息
        total = len(results)
        abnormal = sum(1 for r in results if r.is_abnormal)
        failed = sum(1 for r in results if not r.success)
        avg_score = sum(r.score for r in results) / total if total > 0 else 0
        
        html = f"""
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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖥️ {title}</h1>
            <div class="subtitle">生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
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
            <div class="summary-card failed">
                <div class="number">{failed}</div>
                <div class="label">连接失败</div>
            </div>
            <div class="summary-card score">
                <div class="number">{avg_score:.0f}</div>
                <div class="label">平均健康分</div>
            </div>
        </div>
        
        <h2 class="section-title">📊 巡检详情</h2>
        <div class="server-list">
"""
        
        # 按分数排序，异常的排前面
        sorted_results = sorted(results, key=lambda x: (x.success, x.score))
        
        for r in sorted_results:
            html += f"""
            <div class="server-card">
                <div class="server-header">
                    <span class="server-host">🖥️ {r.host}</span>
                    <div class="server-score">
                        <span class="score-badge" style="color: {r.risk_color}">{r.score}分</span>
                        <span class="risk-badge" style="background: {r.risk_color}; color: #fff">{r.risk_level}</span>
                    </div>
                </div>
                <div class="server-body">
                    <div class="metrics">
                        <div class="metric">
                            <div class="metric-label">CPU使用率</div>
                            <div class="metric-value">{f'{r.cpu_percent:.1f}%' if r.cpu_percent is not None else 'N/A'}</div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">内存使用率</div>
                            <div class="metric-value">{f'{r.memory_percent:.1f}%' if r.memory_percent is not None else 'N/A'}</div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">僵尸进程</div>
                            <div class="metric-value">{r.zombie_count}</div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">巡检时间</div>
                            <div class="metric-value" style="font-size: 0.9em">{r.timestamp}</div>
                        </div>
                    </div>
"""
            
            # 磁盘使用情况
            if r.disk_usage:
                html += '<div class="metrics">'
                for mount, usage in r.disk_usage.items():
                    color = "#ff6b6b" if usage > THRESHOLDS["disk_percent"] else "#4ecdc4"
                    html += f'''
                        <div class="metric">
                            <div class="metric-label">磁盘 {mount}</div>
                            <div class="metric-value" style="color: {color}">{usage:.1f}%</div>
                        </div>
'''
                html += '</div>'
            
            # 错误信息
            if r.errors:
                html += '''
                    <div class="errors">
                        <div class="errors-title">❌ 异常项目</div>
'''
                for error in r.errors:
                    html += f'<div class="error-item">• {error}</div>'
                html += '</div>'
            
            # 警告信息
            if r.warnings:
                html += '''
                    <div class="warnings">
                        <div class="warnings-title">⚠️ 警告项目</div>
'''
                for warning in r.warnings:
                    html += f'<div class="warning-item">• {warning}</div>'
                html += '</div>'
            
            if not r.errors and not r.warnings:
                html += '<div class="no-issues">✅ 所有指标正常</div>'
            
            html += """
                </div>
            </div>
"""
        
        html += f"""
        </div>
        
        <div class="footer">
            <p>服务器自动化巡检系统 | Generated by Server Inspector</p>
        </div>
    </div>
</body>
</html>
"""
        return html


class EmailSender:
    """邮件发送器"""
    
    def __init__(self, smtp_host: str, smtp_port: int, username: str, password: str, use_ssl: bool = True):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
    
    def send(self, to_addrs: list[str], subject: str, html_content: str, from_name: str = "服务器巡检系统"):
        """发送HTML邮件"""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{from_name} <{self.username}>"
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
            print(f"✅ 邮件发送成功: {', '.join(to_addrs)}")
        finally:
            server.quit()


def load_servers_from_file(file_path: str) -> list[ServerConfig]:
    """从JSON文件加载服务器配置"""
    with open(file_path, "r", encoding="utf-8") as f:
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


def run_inspection(servers: list[ServerConfig], max_workers: int = 10) -> list[InspectionResult]:
    """并发执行巡检"""
    inspector = ServerInspector()
    results = []
    
    print(f"\n🚀 开始巡检 {len(servers)} 台服务器 (并发数: {max_workers})")
    print("-" * 50)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_server = {
            executor.submit(inspector.inspect, server): server 
            for server in servers
        }
        
        for future in as_completed(future_to_server):
            server = future_to_server[future]
            try:
                result = future.result()
                results.append(result)
                
                status = "✅" if not result.is_abnormal else "❌"
                print(f"{status} {server.host}: 评分 {result.score}, {result.risk_level}")
                
            except Exception as e:
                # 即使future.result()出错也要记录
                result = InspectionResult(host=server.host, success=False)
                result.add_error(f"执行异常: {str(e)}", score_penalty=100)
                results.append(result)
                print(f"❌ {server.host}: 执行异常 - {str(e)}")
    
    print("-" * 50)
    print(f"✅ 巡检完成: 共 {len(results)} 台, 异常 {sum(1 for r in results if r.is_abnormal)} 台")
    
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
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(html_report)
        print(f"📄 报告已保存: {args.output}")
    
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
                subject=f"{args.mail_subject} - {datetime.now().strftime('%Y-%m-%d')}",
                html_content=html_report,
            )
        except Exception as e:
            print(f"❌ 邮件发送失败: {str(e)}")
    elif args.mail_to:
        print("⚠️  需要提供SMTP配置才能发送邮件")


if __name__ == "__main__":
    main()
