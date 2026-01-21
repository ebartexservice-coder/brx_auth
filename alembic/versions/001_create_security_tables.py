"""Create security tables (refresh_tokens, login_audit_logs, rate_limit_events)

Revision ID: 001_create_security_tables
Revises: 
Create Date: 2026-01-21 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = '001_create_security_tables'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create refresh_tokens table
    op.create_table(
        'refresh_tokens',
        sa.Column('id', mysql.BIGINT(unsigned=True), autoincrement=True, nullable=False),
        sa.Column('user_id', mysql.BIGINT(unsigned=True), nullable=False),
        sa.Column('token', sa.String(length=255), nullable=False),
        sa.Column('token_hash', sa.String(length=255), nullable=False, comment='SHA256 hash of the token for lookup'),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_reason', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token'),
        comment='Refresh tokens for dual token authentication system'
    )
    op.create_index('idx_refresh_tokens_user_expires', 'refresh_tokens', ['user_id', 'expires_at'])
    op.create_index('idx_refresh_tokens_token_hash', 'refresh_tokens', ['token_hash'])
    op.create_index('idx_refresh_tokens_revoked', 'refresh_tokens', ['revoked_at'])
    op.create_index(op.f('ix_refresh_tokens_user_id'), 'refresh_tokens', ['user_id'])
    op.create_index(op.f('ix_refresh_tokens_expires_at'), 'refresh_tokens', ['expires_at'])
    op.create_index(op.f('ix_refresh_tokens_token'), 'refresh_tokens', ['token'])

    # Create login_audit_logs table
    op.create_table(
        'login_audit_logs',
        sa.Column('id', mysql.BIGINT(unsigned=True), autoincrement=True, nullable=False),
        sa.Column('user_id', mysql.BIGINT(unsigned=True), nullable=True),
        sa.Column('email', sa.String(length=255), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('failure_reason', sa.String(length=255), nullable=True),
        sa.Column('device_info', sa.Text(), nullable=True),
        sa.Column('location_info', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        comment='Audit log for all login attempts (successful and failed)'
    )
    op.create_index('idx_login_audit_user_created', 'login_audit_logs', ['user_id', 'created_at'])
    op.create_index('idx_login_audit_ip_created', 'login_audit_logs', ['ip_address', 'created_at'])
    op.create_index('idx_login_audit_email_created', 'login_audit_logs', ['email', 'created_at'])
    op.create_index(op.f('ix_login_audit_logs_user_id'), 'login_audit_logs', ['user_id'])
    op.create_index(op.f('ix_login_audit_logs_ip_address'), 'login_audit_logs', ['ip_address'])
    op.create_index(op.f('ix_login_audit_logs_email'), 'login_audit_logs', ['email'])
    op.create_index(op.f('ix_login_audit_logs_success'), 'login_audit_logs', ['success'])
    op.create_index(op.f('ix_login_audit_logs_created_at'), 'login_audit_logs', ['created_at'])

    # Create rate_limit_events table
    op.create_table(
        'rate_limit_events',
        sa.Column('id', mysql.BIGINT(unsigned=True), autoincrement=True, nullable=False),
        sa.Column('identifier', sa.String(length=255), nullable=False, comment='IP address, email, or user_id'),
        sa.Column('event_type', sa.String(length=50), nullable=False, comment='login_attempt, api_request, etc.'),
        sa.Column('count', mysql.BIGINT(), server_default=sa.text('1'), nullable=False),
        sa.Column('window_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('window_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        comment='Rate limiting events tracking for brute force protection'
    )
    op.create_index('idx_rate_limit_identifier_type', 'rate_limit_events', ['identifier', 'event_type'])
    op.create_index('idx_rate_limit_window', 'rate_limit_events', ['window_start', 'window_end'])
    op.create_index(op.f('ix_rate_limit_events_identifier'), 'rate_limit_events', ['identifier'])
    op.create_index(op.f('ix_rate_limit_events_event_type'), 'rate_limit_events', ['event_type'])
    op.create_index(op.f('ix_rate_limit_events_window_start'), 'rate_limit_events', ['window_start'])
    op.create_index(op.f('ix_rate_limit_events_window_end'), 'rate_limit_events', ['window_end'])


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_index(op.f('ix_rate_limit_events_window_end'), table_name='rate_limit_events')
    op.drop_index(op.f('ix_rate_limit_events_window_start'), table_name='rate_limit_events')
    op.drop_index(op.f('ix_rate_limit_events_event_type'), table_name='rate_limit_events')
    op.drop_index(op.f('ix_rate_limit_events_identifier'), table_name='rate_limit_events')
    op.drop_index('idx_rate_limit_window', table_name='rate_limit_events')
    op.drop_index('idx_rate_limit_identifier_type', table_name='rate_limit_events')
    op.drop_table('rate_limit_events')

    op.drop_index(op.f('ix_login_audit_logs_created_at'), table_name='login_audit_logs')
    op.drop_index(op.f('ix_login_audit_logs_success'), table_name='login_audit_logs')
    op.drop_index(op.f('ix_login_audit_logs_email'), table_name='login_audit_logs')
    op.drop_index(op.f('ix_login_audit_logs_ip_address'), table_name='login_audit_logs')
    op.drop_index(op.f('ix_login_audit_logs_user_id'), table_name='login_audit_logs')
    op.drop_index('idx_login_audit_email_created', table_name='login_audit_logs')
    op.drop_index('idx_login_audit_ip_created', table_name='login_audit_logs')
    op.drop_index('idx_login_audit_user_created', table_name='login_audit_logs')
    op.drop_table('login_audit_logs')

    op.drop_index(op.f('ix_refresh_tokens_token'), table_name='refresh_tokens')
    op.drop_index(op.f('ix_refresh_tokens_expires_at'), table_name='refresh_tokens')
    op.drop_index(op.f('ix_refresh_tokens_user_id'), table_name='refresh_tokens')
    op.drop_index('idx_refresh_tokens_revoked', table_name='refresh_tokens')
    op.drop_index('idx_refresh_tokens_token_hash', table_name='refresh_tokens')
    op.drop_index('idx_refresh_tokens_user_expires', table_name='refresh_tokens')
    op.drop_table('refresh_tokens')
