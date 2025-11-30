import socket
import time
import os
import django
from datetime import datetime

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netlogs.settings')
django.setup()

from devices.models import Device
from logs.clickhouse_client import ClickHouseClient

def send_syslog(ip, message, port=514):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode('utf-8'), ('127.0.0.1', port))
    sock.close()

def verify():
    print("Starting Fortinet verification...")
    
    # 1. Setup Device
    ip = '127.0.0.1'
    device, created = Device.objects.get_or_create(ip_address=ip)
    device.status = 'APPROVED'
    device.parser = 'FORTINET'
    device.save()
    print(f"Device {ip} configured with FORTINET parser.")
    
    # 2. Send Fortinet Log
    # Sample from user request
    # date=2023-10-11 time=22:14:15 devname="FG100D" devid="FG100D3G16804432" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1697062455337451761 tz="+0800" srcip=10.1.100.199 srcport=62293 srcintf="port2" srcintfrole="lan" dstip=172.217.160.142 dstport=443 dstintf="wan1" dstintfrole="wan" poluuid="0959739c-662b-51ee-7863-717377474654" sessionid=46336 proto=6 action="accept" policyid=1 policytype="policy" service="HTTPS" dstcountry="United States" srccountry="Reserved" trandisp="snat" transip=192.168.1.110 transport=62293 appid=41469 app="Gmail" appcat="Email" apprisk="medium" applist="default"
    
    msg_body = 'date=2023-10-11 time=22:14:15 devname="FG100D" devid="FG100D3G16804432" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.1.100.199 dstip=172.217.160.142 action="accept" app="Gmail"'
    syslog_msg = f'<189>{msg_body}'
    
    print("Sending Fortinet log...")
    send_syslog(ip, syslog_msg)
    
    # Wait for flush
    time.sleep(6)
    
    # 3. Verify ClickHouse
    print("Checking ClickHouse...")
    logs = ClickHouseClient.get_recent_logs(limit=10)
    
    # We need to check parsed_data, but get_recent_logs only returns specific columns.
    # Let's query directly.
    client = ClickHouseClient.get_client()
    query = "SELECT parsed_data FROM syslogs WHERE message LIKE '%FG100D%' ORDER BY timestamp DESC LIMIT 1"
    result = client.query(query).named_results()
    
    if not result:
        print("FAIL: Log not found.")
        return

    parsed = result[0]['parsed_data']
    print(f"Parsed Data: {parsed}")
    
    if parsed.get('devname') == 'FG100D' and parsed.get('app') == 'Gmail':
        print("PASS: Fortinet log parsed successfully.")
    else:
        print("FAIL: Parsing mismatch.")

if __name__ == '__main__':
    verify()
