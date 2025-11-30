from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import Device
from logs.clickhouse_client import ClickHouseClient
import logging

logger = logging.getLogger(__name__)


def device_list(request):
    devices = Device.objects.all().order_by('-created_at')

    # Get storage statistics from ClickHouse
    try:
        storage_stats = ClickHouseClient.get_storage_stats()
        per_device_storage = ClickHouseClient.get_per_device_storage()

        # Create a lookup dict for per-device storage
        device_storage_map = {
            item['device_ip']: item for item in per_device_storage
        }
    except Exception as e:
        logger.error(f"Failed to get storage stats: {e}")
        storage_stats = {
            'compressed_size': 'N/A',
            'uncompressed_size': 'N/A',
            'total_rows': 0,
            'compression_ratio': 0,
            'compressed_bytes': 0,
            'uncompressed_bytes': 0
        }
        device_storage_map = {}

    return render(request, 'devices/device_list.html', {
        'devices': devices,
        'storage_stats': storage_stats,
        'device_storage_map': device_storage_map,
    })

def approve_device(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    device.status = 'APPROVED'
    device.save()
    messages.success(request, f'Device {device.ip_address} approved.')
    return redirect('device_list')

def reject_device(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    device.status = 'REJECTED'
    device.save()
    messages.warning(request, f'Device {device.ip_address} rejected.')
    return redirect('device_list')

def edit_device(request, device_id):
    device = get_object_or_404(Device, id=device_id)

    if request.method == 'POST':
        device.hostname = request.POST.get('hostname')
        device.parser = request.POST.get('parser')

        # Handle retention_days
        retention_days = request.POST.get('retention_days')
        if retention_days is not None:
            try:
                device.retention_days = int(retention_days)
            except (ValueError, TypeError):
                pass

        device.save()
        messages.success(request, f'Device {device.ip_address} updated.')
        return redirect('device_list')

    # Get storage stats for this device
    device_storage = None
    try:
        per_device_storage = ClickHouseClient.get_per_device_storage()
        for item in per_device_storage:
            if item['device_ip'] == str(device.ip_address):
                device_storage = item
                break
    except Exception as e:
        logger.error(f"Failed to get device storage stats: {e}")

    return render(request, 'devices/edit_device.html', {
        'device': device,
        'device_storage': device_storage,
    })
