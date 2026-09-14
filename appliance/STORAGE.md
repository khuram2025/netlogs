# ZenShield storage management

Install the latest signed update from **System → Updates**, then open **System → Storage**. These capabilities are included in ZenShield 0.4.1.

## A large system disk with a small filesystem

The hypervisor's disk size is not the same as filesystem capacity. For example, Ubuntu can have a 300 GiB disk with only a 14 GiB root logical volume. This disk contains the operating system and must not be initialized as a blank data disk.

1. Choose **Rescan attached and expanded disks** and confirm the displayed operation.
2. Review the **System filesystem** capacity and available expansion.
3. Choose **Grow system filesystem** and review the confirmation. For a supported Ubuntu LVM layout, this expands the final partition and physical volume where needed, then allocates unused space in the system volume group to the root logical volume. Other logical volumes are preserved.
4. Wait for the operation to complete. The system filesystem capacity increases, and application data stored on that filesystem can use the new space.

Supported automatic layouts are an ext4 or XFS root on the final physical partition, or a standard linear root logical volume in a single-PV system volume group. Encrypted, RAID, thin-provisioned and multi-PV system layouts require administrator maintenance. Ubuntu's `cloud-guest-utils` provides partition growth; the confirmed operation installs it from configured Ubuntu repositories if needed. XFS requires `xfsprogs`.

## A separate data pool

1. Attach a new, blank virtual disk. Choose **Rescan attached and expanded disks**.
2. Choose **Initialize pool** on the blank disk and review its identity carefully.
3. Confirm the displayed phrase. Services pause while ClickHouse, PostgreSQL, Redis, application logs and application credentials are copied and verified.
4. Services restart on the managed data volumes. The original Docker volumes remain available for recovery.

The disk must have enough space for the existing data, filesystem overhead and migration headroom. There is no fixed 16 GiB minimum. A failed or interrupted staged initialization can be retried with **Retry data migration**; recognized existing filesystems are preserved. If a disk or volume identity has changed, the appliance refuses automatic recovery.

## Expand a managed pool

After increasing a data disk in the hypervisor, choose **Rescan attached and expanded disks**. Extra space appears under **Available to allocate**. Choose **Extend volume** for ClickHouse or application storage and enter the new total size in GiB.

Alternatively, attach a blank disk, rescan, and choose **Add to pool**. Adding capacity does not automatically assign all of it to a volume. Keep every pool disk attached. Disk removal and shrinking are not supported.

## Reporting and retention

**Storage Monitor** reports the host filesystem containing ClickHouse data. **Partitions** lists actual host mounts, including the system filesystem and managed data volumes. Filesystem overhead and reserved blocks mean usable capacity is smaller than the physical disk or logical volume size.

A log quota controls retention; it does not allocate disk space. When a configured quota exceeds filesystem capacity, lower the quota or expand storage. The monitor displays a warning. DNS source retention remains separate from the syslog quota.

## Console commands

```text
show storage
storage rescan
storage grow-system
storage grow clickhouse 100
storage grow application 30
storage migrate
```

Changes require the displayed confirmation phrase. `show storage` includes operation progress and any failure reason. Keep a current backup before making storage changes. If an operation reports a missing disk or mount, restore the expected disk before retrying; do not initialize a disk containing existing data.
