#!/bin/bash
# =============================================================================
# create-ova.sh — Convert QCOW2 → VMDK → OVF → OVA
#
# Creates VMware/VirtualBox compatible OVA from QCOW2 disk image.
#
# Usage:
#   ./create-ova.sh <qcow2-file> <version> [output-dir]
#
# Requires: qemu-img, tar, sha256sum
# =============================================================================
set -euo pipefail

QCOW2_FILE="${1:?Usage: $0 <qcow2-file> <version> [output-dir]}"
VERSION="${2:?Usage: $0 <qcow2-file> <version> [output-dir]}"
OUTPUT_DIR="${3:-.}"

VMDK_FILE="$OUTPUT_DIR/zentryc-${VERSION}-disk1.vmdk"
OVF_FILE="$OUTPUT_DIR/zentryc-${VERSION}.ovf"
MF_FILE="$OUTPUT_DIR/zentryc-${VERSION}.mf"
OVA_FILE="$OUTPUT_DIR/zentryc-${VERSION}.ova"

echo "==> Creating OVA from QCOW2..."
echo "  Input:   $QCOW2_FILE"
echo "  Version: $VERSION"
echo "  Output:  $OVA_FILE"

# ── Step 1: Convert QCOW2 → VMDK ──────────────────────────────────
echo "  Converting QCOW2 → VMDK..."
qemu-img convert -f qcow2 -O vmdk -o subformat=streamOptimized \
    "$QCOW2_FILE" "$VMDK_FILE"

VMDK_SIZE=$(stat -c%s "$VMDK_FILE")
echo "  VMDK size: $((VMDK_SIZE / 1048576))MB"

# ── Step 2: Create OVF descriptor ─────────────────────────────────
echo "  Generating OVF descriptor..."
VMDK_BASENAME=$(basename "$VMDK_FILE")

cat > "$OVF_FILE" <<OVFEOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common"
          xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
          xmlns:vmw="http://www.vmware.com/schema/ovf"
          xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="${VMDK_BASENAME}" ovf:id="file1" ovf:size="${VMDK_SIZE}"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="42949672960" ovf:capacityAllocationUnits="byte"
          ovf:diskId="vmdisk1" ovf:fileRef="file1"
          ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="VM Network">
      <Description>The VM Network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="zentryc-${VERSION}">
    <Info>Zentryc SOAR/SIEM Platform v${VERSION}</Info>
    <Name>Zentryc ${VERSION}</Name>
    <OperatingSystemSection ovf:id="96" vmw:osType="ubuntu64Guest">
      <Info>The kind of installed guest operating system</Info>
      <Description>Ubuntu Linux (64-bit)</Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>zentryc-${VERSION}</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-13</vssd:VirtualSystemType>
      </System>
      <!-- 2 vCPUs -->
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>2 virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>2</rasd:VirtualQuantity>
      </Item>
      <!-- 4GB RAM -->
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>4096MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>4096</rasd:VirtualQuantity>
      </Item>
      <!-- SCSI Controller -->
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>
      <!-- Disk -->
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <!-- NIC -->
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection>
        <rasd:Description>E1000 ethernet adapter</rasd:Description>
        <rasd:ElementName>Network adapter 1</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceSubType>E1000</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
OVFEOF

# ── Step 3: Create manifest ───────────────────────────────────────
echo "  Generating manifest..."
OVF_BASENAME=$(basename "$OVF_FILE")
OVF_SHA256=$(sha256sum "$OVF_FILE" | awk '{print $1}')
VMDK_SHA256=$(sha256sum "$VMDK_FILE" | awk '{print $1}')

cat > "$MF_FILE" <<MFEOF
SHA256(${OVF_BASENAME})= ${OVF_SHA256}
SHA256(${VMDK_BASENAME})= ${VMDK_SHA256}
MFEOF

# ── Step 4: Create OVA (tar archive) ──────────────────────────────
echo "  Creating OVA archive..."
cd "$OUTPUT_DIR"
tar -cf "$(basename "$OVA_FILE")" \
    "$(basename "$OVF_FILE")" \
    "$(basename "$VMDK_FILE")" \
    "$(basename "$MF_FILE")"

# Clean up intermediate files
rm -f "$VMDK_FILE" "$OVF_FILE" "$MF_FILE"

OVA_SIZE=$(stat -c%s "$OVA_FILE")
echo ""
echo "==> OVA created: $OVA_FILE ($((OVA_SIZE / 1048576))MB)"
