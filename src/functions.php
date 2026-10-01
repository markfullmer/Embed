<?php
declare(strict_types = 1);

namespace Embed;

use Psr\Http\Message\UriInterface;

function clean(string $value, bool $allowHTML = false): ?string
{
    $value = trim($value);

    if (!$allowHTML) {
        $value = html_entity_decode($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401);
        $value = strip_tags($value);
    }

    $replaced = preg_replace('/\s+/u', ' ', $value);
    $value = trim($replaced !== null ? $replaced : $value);
    return $value === '' ? null : $value;
}

/**
 * @param array<string, mixed> $attributes
 */
function html(string $tagName, array $attributes, ?string $content = null): string
{
    $html = "<{$tagName}";

    foreach ($attributes as $name => $value) {
        if ($value === null) {
            continue;
        } elseif ($value === true) {
            $html .= " $name";
        } elseif ($value !== false) {
            if (is_string($value)) {
                $stringValue = $value;
            } elseif (is_scalar($value)) {
                $stringValue = (string) $value;
            } elseif (is_object($value) && method_exists($value, '__toString')) {
                $stringValue = (string) $value;
            } else {
                $stringValue = '';
            }
            $html .= ' '.$name.'="'.htmlspecialchars($stringValue).'"';
        }
    }

    if ($tagName === 'img') {
        return "$html />";
    }

    return "{$html}>{$content}</{$tagName}>";
}

/**
 * Resolve a uri within this document
 * (useful to get absolute uris from relative)
 */
function resolveUri(UriInterface $base, UriInterface $uri): UriInterface
{
    $uri = $uri->withPath(resolvePath($base->getPath(), $uri->getPath()));

    if ($uri->getHost() === '') {
        $uri = $uri->withHost($base->getHost());
    }

    if ($uri->getScheme() === '') {
        $uri = $uri->withScheme($base->getScheme());
    }

    return $uri
        ->withPath(cleanPath($uri->getPath()))
        ->withFragment('');
}

/**
 * Check if the DNS associated with the URL is valid (SSRF).
 */
function isValidUrl(string $url): bool
{
    // First, use standard PHP url filtering.
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return false;
    }
    // Next, check the host for problematic IPs.
    $parts = parse_url($url);
    if (empty($parts['host'])) {
        // This would be an internal Url, which is valid.
        return false;
    }
    $host = $parts['host'];
    // Normalize IPv6 literal formatting wrapping (e.g., [::1] -> ::1)
    if (strpos($host, '[') === 0 && strpos($host, ']') === (strlen($host) - 1)) {
        $host = substr($host, 1, -1);
    }
    // Collect all IPs the host resolves to.
    $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        // The host is already a direct IP address literal.
        $ips[] = $host;
    }
    else {
        // Resolve DNS records for both IPv4 (A) and IPv6 (AAAA).
        $dnsA = @dns_get_record($host, DNS_A);
        $dnsAAAA = @dns_get_record($host, DNS_AAAA);
        if (is_array($dnsA)) {
            foreach ($dnsA as $record) {
                if (isset($record['ip'])) {
                     $ips[] = $record['ip'];
                }
            }
        }
        if (is_array($dnsAAAA)) {
            foreach ($dnsAAAA as $record) {
                if (isset($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }
        // Fallback. If dns_get_record fails but gethostbyname finds something.
        if (empty($ips)) {
            $fallbackIp = @gethostbyname($host);
            if ($fallbackIp !== $host) {
                $ips[] = $fallbackIp;
            }
            else {
                // If DNS resolution fails, treat URL as invalid.
                return false;
            }
        }
    }
    // 4. Validate resolved IPs against standard restricted ranges
    foreach ($ips as $ip) {
        // Check if the IP is valid and falls outside reserved/private scopes
        // FILTER_FLAG_NO_PRIV_RANGE: Blocks RFC1918 (10/8, 172.16/12, 192.168/16)
        // FILTER_FLAG_NO_RES_RANGE: Blocks Loopback (127.0.0.0/8, ::1)
        // and Link-Local (169.254.0.0/16).
        $isPublic = filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
        if (!$isPublic) {
            // The IP belongs to a restricted/private range.
            return false;
        }
    }
    return true;
}

function isHttp(string $uri): bool
{
    $result = preg_match('/^(\w+):/', $uri, $matches);
    if ($result === 1) {
        $scheme = strtolower($matches[1]);
        return in_array($scheme, ['http', 'https'], true);
    }

    // SECURE: Reject URIs without explicit http/https scheme
    return false;
}

function resolvePath(string $base, string $path): string
{
    if ($path === '') {
        return '';
    }

    if ($path[0] === '/') {
        return $path;
    }

    if (substr($base, -1) !== '/') {
        $position = strrpos($base, '/');
        $base = $position !== false ? substr($base, 0, $position) : '';
    }

    $path = "{$base}/{$path}";

    $parts = array_filter(explode('/', $path), static function (string $value): bool {
        return strlen($value) > 0;
    });
    $absolutes = [];

    foreach ($parts as $part) {
        if ('.' === $part) {
            continue;
        }

        if ('..' === $part) {
            array_pop($absolutes);
            continue;
        }

        $absolutes[] = $part;
    }

    return implode('/', $absolutes);
}

function cleanPath(?string $path): string
{
    if ($path === null || $path === '') {
        return '/';
    }

    $cleanedPath = preg_replace('|[/]{2,}|', '/', $path);
    if ($cleanedPath === null) {
        return '/';
    }
    $path = $cleanedPath;

    if (strpos($path, ';jsessionid=') !== false) {
        $cleanedPath = preg_replace('/^(.*)(;jsessionid=.*)$/i', '$1', $path);
        if ($cleanedPath !== null) {
            $path = $cleanedPath;
        }
    }

    return $path;
}

function matchPath(string $pattern, string $subject): bool
{
    $pattern = str_replace('\\*', '.*', preg_quote($pattern, '|'));

    return (bool) preg_match("|^{$pattern}$|i", $subject);
}

function getDirectory(string $path, int $position): ?string
{
    $dirs = explode('/', $path);
    return $dirs[$position + 1] ?? null;
}

/**
 * Determine whether at least one of the supplied variables is empty.
 *
 * @param mixed ...$values The values to check.
 *
 * @return boolean
 */
function isEmpty(...$values): bool
{
    $skipValues = array(
        'undefined',
    );

    foreach ($values as $value) {
        if ($value === null || $value === '' || $value === [] || $value === false || $value === 0 || $value === 0.0 || $value === '0' || in_array($value, $skipValues, true)) {
            return true;
        }
    }

    return false;
}

if (!function_exists("array_is_list")) {
    /**
     * Polyfil for https://www.php.net/manual/en/function.array-is-list.php
     * which is only available in PHP 8.1+
     *
     * @param      array<mixed, mixed>  $array  The array
     *
     * @return     bool
     */
    function array_is_list(array $array): bool
    {
        $i = -1;
        foreach ($array as $k => $v) {
            ++$i;
            if ($k !== $i) {
                return false;
            }
        }
        return true;
    }
}
