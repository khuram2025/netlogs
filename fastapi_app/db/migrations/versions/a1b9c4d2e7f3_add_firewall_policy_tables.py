"""Add firewall policy / rule-base tables

Revision ID: a1b9c4d2e7f3
Revises: e9a05a29e536
Create Date: 2026-04-19 14:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b9c4d2e7f3'
down_revision: Union[str, Sequence[str], None] = 'e9a05a29e536'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── snapshots ────────────────────────────────────────────────
    op.create_table(
        'firewall_policy_snapshots',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('vdom', sa.String(length=100), nullable=True),
        sa.Column('raw_output', sa.Text(), nullable=True),
        sa.Column('policy_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('address_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('addrgrp_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('service_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('servicegrp_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('fetched_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('fetch_duration_ms', sa.Integer(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['devices_device.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_fwpolicy_snap_device', 'firewall_policy_snapshots', ['device_id'])
    op.create_index('idx_fwpolicy_snap_device_time', 'firewall_policy_snapshots', ['device_id', 'fetched_at'])
    op.create_index('idx_fwpolicy_snap_vdom', 'firewall_policy_snapshots', ['device_id', 'vdom'])

    # ── policies (rule base) ─────────────────────────────────────
    op.create_table(
        'firewall_policies',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('snapshot_id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('vdom', sa.String(length=100), nullable=True),
        sa.Column('rule_id', sa.String(length=100), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('position', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('action', sa.String(length=20), nullable=False, server_default='accept'),
        sa.Column('src_zones', sa.JSON(), nullable=True),
        sa.Column('dst_zones', sa.JSON(), nullable=True),
        sa.Column('src_addresses', sa.JSON(), nullable=True),
        sa.Column('dst_addresses', sa.JSON(), nullable=True),
        sa.Column('services', sa.JSON(), nullable=True),
        sa.Column('applications', sa.JSON(), nullable=True),
        sa.Column('users', sa.JSON(), nullable=True),
        sa.Column('nat_enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('log_traffic', sa.String(length=20), nullable=True),
        sa.Column('schedule', sa.String(length=100), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('hit_count', sa.BigInteger(), nullable=True),
        sa.Column('last_hit_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('raw_definition', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['snapshot_id'], ['firewall_policy_snapshots.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['device_id'], ['devices_device.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_fwpolicy_device', 'firewall_policies', ['device_id'])
    op.create_index('idx_fwpolicy_snapshot', 'firewall_policies', ['snapshot_id'])
    op.create_index('idx_fwpolicy_device_vdom_pos', 'firewall_policies', ['device_id', 'vdom', 'position'])
    op.create_index('idx_fwpolicy_action', 'firewall_policies', ['action'])
    op.create_index('idx_fwpolicy_name', 'firewall_policies', ['name'])

    # ── address objects ──────────────────────────────────────────
    op.create_table(
        'firewall_address_objects',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('snapshot_id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('vdom', sa.String(length=100), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('kind', sa.String(length=30), nullable=False, server_default='ipmask'),
        sa.Column('value', sa.String(length=255), nullable=True),
        sa.Column('members', sa.JSON(), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('raw_definition', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['snapshot_id'], ['firewall_policy_snapshots.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['device_id'], ['devices_device.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_fwaddr_device', 'firewall_address_objects', ['device_id'])
    op.create_index('idx_fwaddr_snapshot', 'firewall_address_objects', ['snapshot_id'])
    op.create_index('idx_fwaddr_device_name', 'firewall_address_objects', ['device_id', 'vdom', 'name'])
    op.create_index('idx_fwaddr_kind', 'firewall_address_objects', ['kind'])

    # ── service objects ──────────────────────────────────────────
    op.create_table(
        'firewall_service_objects',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('snapshot_id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('vdom', sa.String(length=100), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('protocol', sa.String(length=20), nullable=False, server_default='tcp'),
        sa.Column('ports', sa.String(length=255), nullable=True),
        sa.Column('members', sa.JSON(), nullable=True),
        sa.Column('category', sa.String(length=100), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('raw_definition', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['snapshot_id'], ['firewall_policy_snapshots.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['device_id'], ['devices_device.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_fwsvc_device', 'firewall_service_objects', ['device_id'])
    op.create_index('idx_fwsvc_snapshot', 'firewall_service_objects', ['snapshot_id'])
    op.create_index('idx_fwsvc_device_name', 'firewall_service_objects', ['device_id', 'vdom', 'name'])
    op.create_index('idx_fwsvc_protocol', 'firewall_service_objects', ['protocol'])


def downgrade() -> None:
    op.drop_table('firewall_service_objects')
    op.drop_table('firewall_address_objects')
    op.drop_table('firewall_policies')
    op.drop_table('firewall_policy_snapshots')
