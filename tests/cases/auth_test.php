<?php
/**
 * Security helpers: client IP resolution (H1), HTTPS detection and the
 * per-session rate limiter used to protect shared provider quotas (H6).
 */
declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/public_html/includes/auth.php';

// Utility: run a callback with a temporary $_SERVER and TDL_TRUST_PROXY value,
// restoring both afterwards so tests stay isolated.
function tdl_with_env(array $server, ?string $trustProxy, callable $fn): void {
    $oldServer = $_SERVER;
    $oldEnv    = getenv('TDL_TRUST_PROXY');
    $_SERVER   = $server;
    if ($trustProxy === null) {
        putenv('TDL_TRUST_PROXY');
    } else {
        putenv('TDL_TRUST_PROXY=' . $trustProxy);
    }
    try {
        $fn();
    } finally {
        $_SERVER = $oldServer;
        if ($oldEnv === false) {
            putenv('TDL_TRUST_PROXY');
        } else {
            putenv('TDL_TRUST_PROXY=' . $oldEnv);
        }
    }
}

test('normalizeDomainSearch unwraps defanged IOCs and URLs', function () {
    assert_same('evil.com', normalizeDomainSearch('https://Evil[.]com/path?x=1'));
    assert_same('my-passkeys.com', normalizeDomainSearch('my-passkeys[.]com'));
    assert_same('foo.bar', normalizeDomainSearch('foo dot bar'));
});

test('getClientIp ignores a spoofed XFF from a non-proxy peer', function () {
    tdl_with_env(
        ['REMOTE_ADDR' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4'],
        null,
        function () {
            assert_same('203.0.113.7', getClientIp());
        }
    );
});

test('getClientIp trusts CF-Connecting-IP behind a Cloudflare peer', function () {
    tdl_with_env(
        [
            'REMOTE_ADDR'           => '173.245.48.10',
            'HTTP_CF_CONNECTING_IP' => '198.51.100.9',
            'HTTP_X_FORWARDED_FOR'  => '1.2.3.4',
        ],
        null,
        function () {
            assert_same('198.51.100.9', getClientIp());
        }
    );
});

test('getClientIp uses the last XFF hop behind Cloudflare', function () {
    tdl_with_env(
        [
            'REMOTE_ADDR'          => '173.245.48.10',
            'HTTP_X_FORWARDED_FOR' => '1.2.3.4, 198.51.100.9',
        ],
        null,
        function () {
            assert_same('198.51.100.9', getClientIp());
        }
    );
});

test('getClientIp ignores proxy headers when TDL_TRUST_PROXY=0', function () {
    tdl_with_env(
        [
            'REMOTE_ADDR'           => '173.245.48.10',
            'HTTP_CF_CONNECTING_IP' => '198.51.100.9',
        ],
        '0',
        function () {
            assert_same('173.245.48.10', getClientIp());
        }
    );
});

test('getClientIp trusts proxy headers when TDL_TRUST_PROXY=1', function () {
    tdl_with_env(
        [
            'REMOTE_ADDR'           => '10.0.0.1',
            'HTTP_CF_CONNECTING_IP' => '198.51.100.9',
        ],
        '1',
        function () {
            assert_same('198.51.100.9', getClientIp());
        }
    );
});

test('tdl_is_cloudflare_ip detects Cloudflare ranges only', function () {
    assert_true(tdl_is_cloudflare_ip('173.245.48.1'));
    assert_true(tdl_is_cloudflare_ip('104.16.0.1'));
    assert_true(tdl_is_cloudflare_ip('2606:4700::1'));
    assert_false(tdl_is_cloudflare_ip('8.8.8.8'));
    assert_false(tdl_is_cloudflare_ip('not-an-ip'));
});

test('tdl_is_https detects direct and proxied HTTPS', function () {
    tdl_with_env(['HTTPS' => 'on'], null, function () {
        assert_true(tdl_is_https());
    });
    tdl_with_env(['SERVER_PORT' => '443'], null, function () {
        assert_true(tdl_is_https());
    });
    tdl_with_env(['HTTP_X_FORWARDED_PROTO' => 'https'], null, function () {
        assert_true(tdl_is_https());
    });
    tdl_with_env(['SERVER_PORT' => '80'], null, function () {
        assert_false(tdl_is_https());
    });
});

test('sessionRateLimited blocks after the configured max', function () {
    $_SESSION = [];
    assert_false(sessionRateLimited('rl_test', 2, 60));
    assert_false(sessionRateLimited('rl_test', 2, 60));
    assert_true(sessionRateLimited('rl_test', 2, 60));
});

test('apiRateLimitMeta reports limit, remaining and reset', function () {
    $meta = apiRateLimitMeta(0, 10, 60, 1000);
    assert_same(10, $meta['limit']);
    assert_same(9, $meta['remaining'], 'first request leaves 9 of 10');
    assert_same(1060, $meta['reset']);

    $mid = apiRateLimitMeta(4, 10, 60, 1000);
    assert_same(5, $mid['remaining']);

    $exhausted = apiRateLimitMeta(10, 10, 60, 1000);
    assert_same(0, $exhausted['remaining'], 'never negative');
});
