"""Tests for shared auth utilities."""

from ldapgate._auth_utils import BasicAuthRateLimiter


def test_rate_limiter_username_log_masking_is_configurable():
    assert BasicAuthRateLimiter()._username_for_log('alice') != 'alice'
    assert BasicAuthRateLimiter(mask_usernames_in_logs=False)._username_for_log('alice') == 'alice'


def test_rate_limiter_shared_state_path_shares_lockouts(tmp_path):
    """Separate limiter instances should share failures through state_path."""
    state_path = tmp_path / 'rate-limit.json'
    limiter_a = BasicAuthRateLimiter(
        max_failures=2,
        window_seconds=300,
        lockout_seconds=60,
        state_path=str(state_path),
    )
    limiter_b = BasicAuthRateLimiter(
        max_failures=2,
        window_seconds=300,
        lockout_seconds=60,
        state_path=str(state_path),
    )

    limiter_a.record_failure('10.0.0.1', 'alice')
    assert not limiter_b.is_locked_out('10.0.0.1', 'alice')

    limiter_b.record_failure('10.0.0.1', 'alice')

    assert limiter_a.is_locked_out('10.0.0.1', 'alice')
    assert limiter_a.is_locked_out('10.0.0.2', 'alice')


def test_rate_limiter_shared_state_success_clears_lockout(tmp_path):
    """A success in one process should clear shared IP and username lockouts."""
    state_path = tmp_path / 'rate-limit.json'
    limiter_a = BasicAuthRateLimiter(
        max_failures=1,
        window_seconds=300,
        lockout_seconds=60,
        state_path=str(state_path),
    )
    limiter_b = BasicAuthRateLimiter(
        max_failures=1,
        window_seconds=300,
        lockout_seconds=60,
        state_path=str(state_path),
    )

    limiter_a.record_failure('10.0.0.1', 'alice')
    assert limiter_b.is_locked_out('10.0.0.1', 'alice')

    limiter_b.record_success('10.0.0.1', 'alice')

    assert not limiter_a.is_locked_out('10.0.0.1', 'alice')
