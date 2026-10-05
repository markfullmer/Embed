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
            ['./foo', true],
            ['/foo', true],
            ['../foo', true],
            ['foo.com', true],
            ['//foo.com', true],
        ];
    }

    public function invalidUrlsProvider(): array {
        return [
            ['https://169.254.0.0/SSRF_PATH', false],
            ['169.254.0.0/SSRF_PATH', false],
            ['https://169.254.169.254/latest/meta-data/iam/security-credentials/', false],
            ['https://127.0.0.1:9999/SSRF_PATH', false],
            ['http://127.0.0.1:9999/SSRF_PATH', false],
            ['https://10.0.0.0/SSRF_PATH', false],
            ['10.0.0.0/SSRF_PATH', false],
            ['https://172.16.0.0/SSRF_PATH', false],
            ['172.16.0.0/SSRF_PATH', false],
            ['https://192.168.0.0/SSRF_PATH', false],
            ['192.168.0.0/SSRF_PATH', false],
            ['http://localhost:8080/admin', false],
            ['https://100.100.100.200', false], // Alibaba metadata
            ['100.100.100.200', false], // Alibaba metadata
            ['64:ff9b::192.0.2.1', false], // embedded IPv4: 192.0.2.1
            ['64:ff9b::192.0.2.1', false], // embedded IPv4: 192.0.2.1
            ['https://64:ff9b::198.51.100.1', false], // embedded IPv4: 198.51.100.1
            ['64:ff9b::198.51.100.1', false], // embedded IPv4: 198.51.100.1
            ['https://198.18.50.25', false],
            ['198.18.50.25', false],
            ['https://198.19.200.10', false],
            ['198.19.200.10', false],
            ['https://100.64.0.1', false],
            ['100.64.0.1', false],
            ['https://100.100.50.25', false],
            ['100.100.50.25', false],
            ['./foo', false],
            ['/foo', false],
            ['../foo', false],
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
