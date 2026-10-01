<?php
declare(strict_types = 1);

namespace Embed\Tests;

use function Embed\isHttp;
use function Embed\isValidUrl;
use PHPUnit\Framework\TestCase;


class FunctionsTest extends TestCase
{
    public function urlsProvider(): array
    {
        return [
            ['https://foo.com', true],
            ['http://foo.com', true],
            ['mailto:foo@example.com', false],
            ['tel:+1234567890', false],
            ['data:foo', false],
            ['./foo', false],
            ['/foo', false],
            ['../foo', false],
            ['foo.com', false],
            ['//foo.com', false],
            ['//internal.local/admin', false],
        ];
    }

    public function invalidUrlsProvider(): array {
        return [
            ['https://169.254.0.0/SSRF_PATH', false],
            ['https://169.254.169.254/latest/meta-data/iam/security-credentials/', false],
            ['https://127.0.0.1:9999/SSRF_PATH', false],
            ['http://127.0.0.1:9999/SSRF_PATH', false],
            ['https://10.0.0.0/SSRF_PATH', false],
            ['https://172.16.0.0/SSRF_PATH', false],
            ['https://192.168.0.0/SSRF_PATH', false],
            ['http://localhost:8080/admin', false],
            ['169.254.0.0/SSRF_PATH', false],
            ['10.0.0.0/SSRF_PATH', false],
            ['172.16.0.0/SSRF_PATH', false],
            ['192.168.0.0/SSRF_PATH', false],
            ['./foo', false],
            ['/foo', false],
            ['../foo', false],
            ['foo.com', false],
            ['https://foo.com', true],
            ['https://example.com', true],
        ];
    }

    /**
     * @dataProvider urlsProvider
     */
    public function testIsHttp(string $url, bool $expected)
    {
        $result = isHttp($url);
        $this->assertSame($expected, $result);
    }

    /**
     * @dataProvider invalidUrlsProvider
     */
    public function testIsValidUrl(string $url, bool $expected)
    {
        $result = isValidUrl($url);
        $this->assertSame($expected, $result);
    }
}
