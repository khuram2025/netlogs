import socket
import time
import os
import django
from datetime import datetime

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zentryc.settings')
django.setup()

from devices.models import Device
from logs.clickhouse_client import ClickHouseClient

def send_syslog(ip, message, port=5140):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode('utf-8'), ('127.0.0.1', port))
    sock.close()

def verify():
    print("Starting verification...")
    
    # Clean up
    Device.objects.all().delete()
    # Note: We are not truncating ClickHouse table to avoid messing with existing data if any, 
    # but for this test we assume clean state or we check for specific logs.
    
    # 1. Send log from unknown device
    print("Sending log from unknown device...")
    # We simulate the IP by binding to it? No, UDP packet source IP is what matters.
    # Since we are sending from localhost, the source IP will be 127.0.0.1.
    # So we will test with 127.0.0.1.
    
    send_syslog('127.0.0.1', '<134>Oct 11 22:14:15 mymachine su: ' + 'su root' + ' failed for lonvick on /dev/pts/8')
    time.sleep(2) # Wait for processing
    
    # Check Device
    device = Device.objects.filter(ip_address='127.0.0.1').first()
    if not device:
        print("FAIL: Device not created.")
        return
    
    if device.status != 'PENDING':
        print(f"FAIL: Device status is {device.status}, expected PENDING.")
        return
        
    print("PASS: Device created as PENDING.")
    
    # 2. Approve Device
    print("Approving device...")
    device.status = 'APPROVED'
    device.save()
    
    # 3. Send log again
    print("Sending log from approved device...")
    test_msg = f"Test Log {datetime.now().timestamp()}"
    send_syslog('127.0.0.1', f'<14>{test_msg}')
    
    # Wait for flush (batch size 100 or 5s interval)
    print("Waiting for flush...")
    time.sleep(6) 
    
    # 4. Check ClickHouse
    print("Checking ClickHouse...")
    logs = ClickHouseClient.get_recent_logs(limit=10)
    found = False
    for log in logs:
        if test_msg in log['message']:
            found = True
            break
            
    if found:
        print("PASS: Log found in ClickHouse.")
    else:
        print("FAIL: Log not found in ClickHouse.")
        print("Recent logs:", logs)

if __name__ == '__main__':
    verify()
