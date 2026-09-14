"""
FirewallPolicyService — orchestrates fetch / parse / store of the firewall
rule base + objects (security policies, address objects, service objects).

Mirrors the shape of RoutingService and ZoneService so the device detail
page can reuse the same fetch/snapshot/history UX patterns.
"""

import asyncio
import logging
import time
from typing import Optional, Tuple, List, Dict, Any

from sqlalchemy import select, delete, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.device import Device, ParserType
from ..models.credential import DeviceCredential, DeviceVdom
from ..models.device_ssh_settings import DeviceSshSettings
from ..models.firewall_policy import (
    FirewallPolicySnapshot, FirewallPolicy,
    FirewallAddressObject, FirewallServiceObject,
)
from .ssh_service import SSHService
from .firewall_policy_parser import (
    FirewallConfigParser, ParsedFirewallConfig,
)

logger = logging.getLogger(__name__)


def _scrub_for_pg_text(s):
    """Strip 0x00 + other C0 control bytes Postgres TEXT can't store.
    Keep \t \n \r — see RoutingService/ZoneService for the same helper."""
    if s is None:
        return None
    if not isinstance(s, str):
        try:
            s = str(s)
        except Exception:
            return None
    return s.translate({i: None for i in range(0x20) if i not in (0x09, 0x0A, 0x0D)})


class FirewallPolicyService:
    """Vendor-aware fetch + persist for the firewall rule base."""

    @staticmethod
    def _fetch_policies_via_fortinet_api(host, credential, vdom):
        """Sync helper run in a thread.
        Returns (success, message, parsed_config, duration_ms, raw_str)."""
        import time as _time
        from .fortinet_api_service import FortinetAPIClient, FortinetAPIError
        client = FortinetAPIClient(
            host=str(host), token=credential.password,
            port=credential.port or 443,
        )
        t0 = _time.time()
        try:
            cfg = client.fetch_policy_bundle(vdom=vdom)
            ms = int((_time.time() - t0) * 1000)
            msg = (
                f"Fetched {len(cfg.policies)} policies, "
                f"{len(cfg.addresses) + len(cfg.address_groups)} address objects, "
                f"{len(cfg.services) + len(cfg.service_groups)} service objects"
            )
            return True, msg, cfg, ms, ""
        except FortinetAPIError as e:
            ms = int((_time.time() - t0) * 1000)
            return False, f"FortiGate API: {e}", None, ms, ""
        except Exception as e:
            ms = int((_time.time() - t0) * 1000)
            return False, f"{type(e).__name__}: {e}", None, ms, ""

    @staticmethod
    def _fetch_policies_via_paloalto_api(host, credential, vdom):
        """Sync helper run in a thread — PAN-OS XML API.

        PAN-OS doesn't care whether the stored credential is labelled
        SSH or API; both routes end at the same admin account. We always
        try the XML API on HTTPS (port 443 unless the credential explicitly
        overrides to an HTTPS mgmt port). Credential semantics:

        - If ``credential.username`` is set, treat it as an admin user and
          call ``keygen`` with (username, password).
        - Otherwise, treat ``credential.password`` as a pre-issued API key.
        """
        import time as _time
        from .paloalto_api_service import PaloAltoAPIClient, PaloAltoAPIError

        # SSH port 22 is meaningless for the XML API. Fall back to 443
        # unless the credential carries an explicit HTTPS mgmt port.
        port = credential.port or 443
        if port == 22:
            port = 443

        if credential.username:
            client = PaloAltoAPIClient(
                host=str(host),
                username=credential.username,
                password=credential.password,
                port=port,
            )
        else:
            client = PaloAltoAPIClient(
                host=str(host),
                api_key=credential.password,
                port=port,
            )

        t0 = _time.time()
        try:
            cfg = client.fetch_policy_bundle(vdom=vdom)
            ms = int((_time.time() - t0) * 1000)
            msg = (
                f"Fetched {len(cfg.policies)} policies, "
                f"{len(cfg.addresses) + len(cfg.address_groups)} address objects, "
                f"{len(cfg.services) + len(cfg.service_groups)} service objects"
            )
            return True, msg, cfg, ms, ""
        except PaloAltoAPIError as e:
            ms = int((_time.time() - t0) * 1000)
            return False, f"PAN-OS API: {e}", None, ms, ""
        except Exception as e:
            ms = int((_time.time() - t0) * 1000)
            return False, f"{type(e).__name__}: {e}", None, ms, ""

    @classmethod
    async def fetch_policies(
        cls,
        device: Device,
        credential: DeviceCredential,
        db: AsyncSession,
        vdom: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[FirewallPolicySnapshot]]:
        start_time = time.time()

        # device.ip_address is INET → IPv4Address; coerce for paramiko.
        ssh_host = str(device.ip_address)
        ssh_host_result = await db.execute(
            select(DeviceSshSettings.ssh_host)
            .where(DeviceSshSettings.device_id == device.id)
            .limit(1)
        )
        override = ssh_host_result.scalar_one_or_none()
        if override:
            o = str(override).strip()
            if o:
                ssh_host = o

        vdom_label = f" (VDOM: {vdom})" if vdom else ""
        transport = (credential.credential_type or "SSH").upper()
        logger.info(
            f"Fetching firewall policies from {device.ip_address} "
            f"({device.parser}){vdom_label} [{transport}]"
        )

        # ── REST/XML API fast-path ─────────────────────────────────
        # FortiGate: opt-in when the credential is labelled "API".
        # PAN-OS: mandatory — there is no SSH policy-fetch flow for it,
        # so we always hit the XML API on HTTPS regardless of credential
        # label (admin user/password works for both SSH and API auth
        # against the same device).
        use_api = False
        api_vendor = None
        if transport == "API" and device.parser == ParserType.FORTINET:
            use_api = True
            api_vendor = "FORTINET"
        elif device.parser == ParserType.PALOALTO:
            use_api = True
            api_vendor = "PALOALTO"

        if use_api:
            if api_vendor == "PALOALTO":
                api_result = await asyncio.to_thread(
                    cls._fetch_policies_via_paloalto_api,
                    ssh_host, credential, vdom,
                )
            else:
                api_result = await asyncio.to_thread(
                    cls._fetch_policies_via_fortinet_api,
                    ssh_host, credential, vdom,
                )
            success, message, cfg, duration_ms, raw = api_result
            credential.last_used = __import__('datetime').datetime.utcnow()
            if not success:
                snap = FirewallPolicySnapshot(
                    device_id=device.id, vdom=vdom,
                    raw_output=_scrub_for_pg_text(raw),
                    policy_count=0, address_count=0, addrgrp_count=0,
                    service_count=0, servicegrp_count=0,
                    fetched_at=__import__('datetime').datetime.utcnow(),
                    fetch_duration_ms=duration_ms,
                    success=False,
                    error_message=_scrub_for_pg_text(message),
                )
                db.add(snap); await db.commit(); await db.refresh(snap)
                return False, message, snap
            credential.last_success = __import__('datetime').datetime.utcnow()

            snap = FirewallPolicySnapshot(
                device_id=device.id, vdom=vdom,
                raw_output=None,  # API path has no useful raw text
                policy_count=len(cfg.policies),
                address_count=len(cfg.addresses),
                addrgrp_count=len(cfg.address_groups),
                service_count=len(cfg.services),
                servicegrp_count=len(cfg.service_groups),
                fetched_at=__import__('datetime').datetime.utcnow(),
                fetch_duration_ms=duration_ms,
                success=True,
            )
            db.add(snap); await db.flush()
            # Bulk-replace existing rows for this device/vdom.
            await db.execute(delete(FirewallPolicy).where(and_(
                FirewallPolicy.device_id == device.id,
                FirewallPolicy.vdom == vdom if vdom else FirewallPolicy.vdom.is_(None),
            )))
            await db.execute(delete(FirewallAddressObject).where(and_(
                FirewallAddressObject.device_id == device.id,
                FirewallAddressObject.vdom == vdom if vdom else FirewallAddressObject.vdom.is_(None),
            )))
            await db.execute(delete(FirewallServiceObject).where(and_(
                FirewallServiceObject.device_id == device.id,
                FirewallServiceObject.vdom == vdom if vdom else FirewallServiceObject.vdom.is_(None),
            )))
            for a in cfg.addresses + cfg.address_groups:
                db.add(FirewallAddressObject(
                    snapshot_id=snap.id, device_id=device.id, vdom=vdom,
                    name=a.name, kind=a.kind, value=a.value,
                    members=a.members or None,
                    comment=_scrub_for_pg_text(a.comment),
                    raw_definition=_scrub_for_pg_text(a.raw_definition),
                ))
            for s in cfg.services + cfg.service_groups:
                db.add(FirewallServiceObject(
                    snapshot_id=snap.id, device_id=device.id, vdom=vdom,
                    name=s.name, protocol=s.protocol, ports=s.ports,
                    members=s.members or None, category=s.category,
                    comment=_scrub_for_pg_text(s.comment),
                    raw_definition=_scrub_for_pg_text(s.raw_definition),
                ))
            for p in cfg.policies:
                db.add(FirewallPolicy(
                    snapshot_id=snap.id, device_id=device.id, vdom=vdom,
                    rule_id=p.rule_id, name=p.name, position=p.position,
                    enabled=p.enabled, action=p.action,
                    src_zones=p.src_zones or None,
                    dst_zones=p.dst_zones or None,
                    src_addresses=p.src_addresses or None,
                    dst_addresses=p.dst_addresses or None,
                    services=p.services or None,
                    applications=p.applications or None,
                    users=p.users or None,
                    nat_enabled=p.nat_enabled,
                    log_traffic=p.log_traffic, schedule=p.schedule,
                    comment=_scrub_for_pg_text(p.comment),
                    raw_definition=_scrub_for_pg_text(p.raw_definition),
                ))
            await db.commit(); await db.refresh(snap)
            return True, message + " via API", snap

        # Vendor branch — Fortinet today; PAN-OS / Cisco land in P2/P3.
        if device.parser == ParserType.FORTINET:
            result = await asyncio.to_thread(
                SSHService.get_fortinet_policies,
                host=ssh_host,
                username=credential.username,
                password=credential.password,
                port=credential.port or 22,
                vdom=vdom,
            )
        else:
            return False, f"Policy fetch not yet supported for {device.parser}", None

        credential.last_used = __import__('datetime').datetime.utcnow()
        fetch_duration = int((time.time() - start_time) * 1000)

        if not result.success:
            snapshot = FirewallPolicySnapshot(
                device_id=device.id,
                vdom=vdom,
                raw_output=_scrub_for_pg_text(result.output),
                policy_count=0,
                address_count=0, addrgrp_count=0,
                service_count=0, servicegrp_count=0,
                fetched_at=__import__('datetime').datetime.utcnow(),
                fetch_duration_ms=fetch_duration,
                success=False,
                error_message=_scrub_for_pg_text(result.error) or "SSH command failed",
            )
            db.add(snapshot)
            await db.commit()
            await db.refresh(snapshot)
            return False, result.error or "SSH command failed", snapshot

        credential.last_success = __import__('datetime').datetime.utcnow()

        cfg: ParsedFirewallConfig = FirewallConfigParser.parse(result.output, device.parser)

        snapshot = FirewallPolicySnapshot(
            device_id=device.id,
            vdom=vdom,
            raw_output=_scrub_for_pg_text(result.output),
            policy_count=len(cfg.policies),
            address_count=len(cfg.addresses),
            addrgrp_count=len(cfg.address_groups),
            service_count=len(cfg.services),
            servicegrp_count=len(cfg.service_groups),
            fetched_at=__import__('datetime').datetime.utcnow(),
            fetch_duration_ms=fetch_duration,
            success=True,
        )
        db.add(snapshot)
        await db.flush()  # snapshot.id

        # Replace this device/vdom's existing rows so the page always
        # reflects the latest snapshot. The FK is ON DELETE CASCADE → the
        # old child rows go with their old snapshot once we wipe them.
        await db.execute(
            delete(FirewallPolicy).where(and_(
                FirewallPolicy.device_id == device.id,
                FirewallPolicy.vdom == vdom if vdom else FirewallPolicy.vdom.is_(None),
            ))
        )
        await db.execute(
            delete(FirewallAddressObject).where(and_(
                FirewallAddressObject.device_id == device.id,
                FirewallAddressObject.vdom == vdom if vdom else FirewallAddressObject.vdom.is_(None),
            ))
        )
        await db.execute(
            delete(FirewallServiceObject).where(and_(
                FirewallServiceObject.device_id == device.id,
                FirewallServiceObject.vdom == vdom if vdom else FirewallServiceObject.vdom.is_(None),
            ))
        )

        for a in cfg.addresses + cfg.address_groups:
            db.add(FirewallAddressObject(
                snapshot_id=snapshot.id, device_id=device.id, vdom=vdom,
                name=a.name, kind=a.kind, value=a.value,
                members=a.members or None,
                comment=_scrub_for_pg_text(a.comment),
                raw_definition=_scrub_for_pg_text(a.raw_definition),
            ))

        for s in cfg.services + cfg.service_groups:
            db.add(FirewallServiceObject(
                snapshot_id=snapshot.id, device_id=device.id, vdom=vdom,
                name=s.name, protocol=s.protocol, ports=s.ports,
                members=s.members or None,
                category=s.category,
                comment=_scrub_for_pg_text(s.comment),
                raw_definition=_scrub_for_pg_text(s.raw_definition),
            ))

        for p in cfg.policies:
            db.add(FirewallPolicy(
                snapshot_id=snapshot.id, device_id=device.id, vdom=vdom,
                rule_id=p.rule_id, name=p.name, position=p.position,
                enabled=p.enabled, action=p.action,
                src_zones=p.src_zones or None,
                dst_zones=p.dst_zones or None,
                src_addresses=p.src_addresses or None,
                dst_addresses=p.dst_addresses or None,
                services=p.services or None,
                applications=p.applications or None,
                users=p.users or None,
                nat_enabled=p.nat_enabled,
                log_traffic=p.log_traffic,
                schedule=p.schedule,
                comment=_scrub_for_pg_text(p.comment),
                raw_definition=_scrub_for_pg_text(p.raw_definition),
            ))

        await db.commit()
        await db.refresh(snapshot)

        logger.info(
            f"Fetched {len(cfg.policies)} policies, {len(cfg.addresses)} addrs, "
            f"{len(cfg.address_groups)} addr-groups, {len(cfg.services)} services, "
            f"{len(cfg.service_groups)} svc-groups from {device.ip_address}"
        )
        msg = (
            f"Fetched {len(cfg.policies)} policies, "
            f"{len(cfg.addresses) + len(cfg.address_groups)} address objects, "
            f"{len(cfg.services) + len(cfg.service_groups)} service objects"
        )
        return True, msg, snapshot

    @classmethod
    async def fetch_all_vdom_policies(
        cls,
        device: Device,
        credential: DeviceCredential,
        db: AsyncSession,
    ) -> Dict[str, Tuple[bool, str, Optional[FirewallPolicySnapshot]]]:
        """Fan out across configured VDOMs (or run a single 'global' fetch)."""
        result_q = await db.execute(
            select(DeviceVdom.vdom_name).where(
                and_(
                    DeviceVdom.device_id == device.id,
                    DeviceVdom.is_active == True,  # noqa: E712
                )
            )
        )
        vdoms: List[str] = [v for (v,) in result_q.all()]
        if not vdoms:
            return {"global": await cls.fetch_policies(device, credential, db, vdom=None)}

        results: Dict[str, Tuple[bool, str, Optional[FirewallPolicySnapshot]]] = {}
        for v in vdoms:
            results[v] = await cls.fetch_policies(device, credential, db, vdom=v)
        return results

    @classmethod
    async def get_latest_snapshot(
        cls, device_id: int, db: AsyncSession, vdom: Optional[str] = None,
    ) -> Optional[FirewallPolicySnapshot]:
        q = (
            select(FirewallPolicySnapshot)
            .where(FirewallPolicySnapshot.device_id == device_id)
            .order_by(desc(FirewallPolicySnapshot.fetched_at))
            .limit(1)
        )
        if vdom:
            q = q.where(FirewallPolicySnapshot.vdom == vdom)
        return (await db.execute(q)).scalar_one_or_none()

    @classmethod
    async def get_policies(
        cls, device_id: int, db: AsyncSession, vdom: Optional[str] = None,
        limit: int = 1000,
    ) -> List[FirewallPolicy]:
        q = select(FirewallPolicy).where(FirewallPolicy.device_id == device_id)
        if vdom:
            q = q.where(FirewallPolicy.vdom == vdom)
        q = q.order_by(FirewallPolicy.position.asc()).limit(limit)
        return list((await db.execute(q)).scalars().all())

    @classmethod
    async def get_address_objects(
        cls, device_id: int, db: AsyncSession, vdom: Optional[str] = None,
    ) -> List[FirewallAddressObject]:
        q = select(FirewallAddressObject).where(FirewallAddressObject.device_id == device_id)
        if vdom:
            q = q.where(FirewallAddressObject.vdom == vdom)
        q = q.order_by(FirewallAddressObject.name.asc())
        return list((await db.execute(q)).scalars().all())

    @classmethod
    async def get_service_objects(
        cls, device_id: int, db: AsyncSession, vdom: Optional[str] = None,
    ) -> List[FirewallServiceObject]:
        q = select(FirewallServiceObject).where(FirewallServiceObject.device_id == device_id)
        if vdom:
            q = q.where(FirewallServiceObject.vdom == vdom)
        q = q.order_by(FirewallServiceObject.name.asc())
        return list((await db.execute(q)).scalars().all())
