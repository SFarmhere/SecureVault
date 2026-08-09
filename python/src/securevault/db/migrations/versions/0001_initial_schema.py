"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-01-01 00:00:00.000000
"""

import json
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

# revision identifiers, used by Alembic.
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Создание начальной схемы: users, keys, containers, audit_entries, policies."""

    # ---------------------------------------------------------------------------
    # users - пользователи системы
    # ---------------------------------------------------------------------------
    op.create_table(
        'users',
        sa.Column('user_id', sa.String(64), primary_key=True),
        sa.Column('username', sa.String(128), nullable=False, unique=True),
        sa.Column('roles', sa.Text, nullable=True, server_default='[]'),
        sa.Column('email', sa.String(255), nullable=True),
        sa.Column('password_hash', sa.String(255), nullable=True),
        sa.Column('public_key', sa.Text, nullable=True),
        sa.Column('created_at', sa.String(64), nullable=False),
        sa.Column('last_login', sa.String(64), nullable=True),
        sa.Column('mfa_enabled', sa.Boolean, nullable=False, server_default=sa.text('0')),
        sa.Column('mfa_secret', sa.String(128), nullable=True),
        sa.Column('status', sa.String(16), nullable=False, server_default='active'),
        sa.Column('failed_attempts', sa.Integer, nullable=False, server_default=sa.text('0')),
        sa.Column('locked_until', sa.String(64), nullable=True),
        sa.Index('ix_users_username', 'username')
    )

    # ---------------------------------------------------------------------------
    # keys - управление ключами (интеграция с key_manager)
    # ---------------------------------------------------------------------------
    op.create_table(
        'keys',
        sa.Column('key_id', sa.String(64), primary_key=True),
        sa.Column('user_id', sa.String(64), sa.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False),
        sa.Column('key_type', sa.String(32), nullable=False),       # aes-256, rsa-2048, ec-p256, kyber1024
        sa.Column('key_alias', sa.String(128), nullable=True),
        sa.Column('key_status', sa.String(16), nullable=False, server_default='active'),  # active, archived, revoked, destroyed
        sa.Column('key_handle', sa.Text, nullable=True),            # ссылка на handle в HSM/токене
        sa.Column('wrapped_key', sa.Text, nullable=True),           # завёрнутый ключ (для резерва)
        sa.Column('security_level', sa.String(16), nullable=False, server_default='CONTAINER'),
        sa.Column('created_at', sa.String(64), nullable=False),
        sa.Column('rotated_at', sa.String(64), nullable=True),
        sa.Column('expires_at', sa.String(64), nullable=True),
        sa.Column('metadata', sa.Text, nullable=True),              # JSON
        sa.Index('ix_keys_user', 'user_id'),
        sa.Index('ix_keys_type', 'key_type')
    )

    # ---------------------------------------------------------------------------
    # containers - виртуальные контейнеры
    # ---------------------------------------------------------------------------
    op.create_table(
        'containers',
        sa.Column('container_id', sa.String(64), primary_key=True),
        sa.Column('owner_id', sa.String(64), sa.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('format', sa.String(8), nullable=False, server_default='V1'),  # V1 / V2
        sa.Column('security_level', sa.String(16), nullable=False, server_default='CONTAINER'),
        sa.Column('path', sa.Text, nullable=True),
        sa.Column('total_size', sa.BigInteger, nullable=False, server_default=sa.text('0')),
        sa.Column('used_size', sa.BigInteger, nullable=False, server_default=sa.text('0')),
        sa.Column('file_count', sa.Integer, nullable=False, server_default=sa.text('0')),
        sa.Column('dedup_enabled', sa.Boolean, nullable=False, server_default=sa.text('1')),
        sa.Column('chunk_size', sa.Integer, nullable=False, server_default=sa.text('65536')),
        sa.Column('compression', sa.String(8), nullable=False, server_default='ZSTD'),
        sa.Column('is_hidden', sa.Boolean, nullable=False, server_default=sa.text('0')),
        sa.Column('is_mounted', sa.Boolean, nullable=False, server_default=sa.text('0')),
        sa.Column('created_at', sa.String(64), nullable=False),
        sa.Column('modified_at', sa.String(64), nullable=True),
        sa.Column('metadata', sa.Text, nullable=True),              # JSON
        sa.Index('ix_containers_owner', 'owner_id')
    )

    # ---------------------------------------------------------------------------
    # audit_entries - цепочка целостности аудита (из AuditRecord)
    # ---------------------------------------------------------------------------
    op.create_table(
        'audit_entries',
        sa.Column('entry_id', sa.String(64), primary_key=True),
        sa.Column('timestamp', sa.String(64), nullable=False),
        sa.Column('user_id', sa.String(64), sa.ForeignKey('users.user_id', ondelete='SET NULL'), nullable=False),
        sa.Column('action', sa.String(128), nullable=False),
        sa.Column('result', sa.String(16), nullable=False),        # success / failed
        sa.Column('event_type', sa.String(64), nullable=False, server_default='operation'),
        sa.Column('severity', sa.String(16), nullable=False, server_default='info'),
        sa.Column('details', sa.Text, nullable=True),              # JSON
        sa.Column('source', sa.String(128), nullable=True),
        sa.Column('prev_hash', sa.String(64), nullable=True),      # hash chain
        sa.Column('entry_hash', sa.String(64), nullable=True),     # SHA-256 текущей записи
        sa.Column('signature', sa.Text, nullable=True),            # ECDSA подпись
        sa.Column('status', sa.String(16), nullable=False, server_default='pending'),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('session_id', sa.String(64), nullable=True),
        sa.Column('request_id', sa.String(64), nullable=True),
        sa.Column('correlation_id', sa.String(64), nullable=True),
        sa.Column('metadata', sa.Text, nullable=True),              # JSON
        sa.Index('ix_audit_user', 'user_id'),
        sa.Index('ix_audit_timestamp', 'timestamp'),
        sa.Index('ix_audit_action', 'action'),
        sa.Index('ix_audit_result', 'result')
    )

    # ---------------------------------------------------------------------------
    # policies - политики безопасности (интеграция с policy_manager)
    # ---------------------------------------------------------------------------
    op.create_table(
        'policies',
        sa.Column('policy_id', sa.String(64), primary_key=True),
        sa.Column('name', sa.String(128), nullable=False, unique=True),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('roles', sa.Text, nullable=True),                 # JSON: список ролей
        sa.Column('allowed_actions', sa.Text, nullable=True),       # JSON: список действий
        sa.Column('allowed_security_levels', sa.Text, nullable=True),  # JSON
        sa.Column('max_key_size', sa.Integer, nullable=True),
        sa.Column('max_file_size', sa.BigInteger, nullable=True),
        sa.Column('require_mfa', sa.Boolean, nullable=False, server_default=sa.text('0')),
        sa.Column('token_required', sa.Boolean, nullable=False, server_default=sa.text('0')),
        sa.Column('is_default', sa.Boolean, nullable=False, server_default=sa.text('0')),
        sa.Column('is_active', sa.Boolean, nullable=False, server_default=sa.text('1')),
        sa.Column('created_at', sa.String(64), nullable=False),
        sa.Column('expires_at', sa.String(64), nullable=True),
        sa.Column('metadata', sa.Text, nullable=True),              # JSON
        sa.Index('ix_policies_name', 'name')
    )

    # ---------------------------------------------------------------------------
    # sessions - активные сессии пользователей (интеграция с session_manager)
    # ---------------------------------------------------------------------------
    op.create_table(
        'sessions',
        sa.Column('session_id', sa.String(64), primary_key=True),
        sa.Column('user_id', sa.String(64), sa.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False),
        sa.Column('token', sa.Text, nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text, nullable=True),
        sa.Column('created_at', sa.String(64), nullable=False),
        sa.Column('expires_at', sa.String(64), nullable=False),
        sa.Column('last_activity', sa.String(64), nullable=True),
        sa.Column('is_active', sa.Boolean, nullable=False, server_default=sa.text('1')),
        sa.Index('ix_sessions_user', 'user_id'),
        sa.Index('ix_sessions_expires', 'expires_at')
    )


def downgrade() -> None:
    """Откат схемы."""
    op.drop_table('sessions')
    op.drop_table('policies')
    op.drop_table('audit_entries')
    op.drop_table('containers')
    op.drop_table('keys')
    op.drop_table('users')