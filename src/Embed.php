<?php
declare(strict_types = 1);

namespace Embed;

use Embed\Http\Crawler;
use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class Embed
{
    private const MAX_HTTP_REDIRECTS = 10;

    private Crawler $crawler;
    private ExtractorFactory $extractorFactory;

    public function __construct(?Crawler $crawler = null, ?ExtractorFactory $extractorFactory = null)
    {
        $this->crawler = $crawler !== null ? $crawler : new Crawler();
        $this->extractorFactory = $extractorFactory !== null ? $extractorFactory : new ExtractorFactory();
    }

    public function get(string $url): Extractor
    {
        if (!isValidUrl($url)) {
            throw new InvalidArgumentException(sprintf('Access to this URL is blocked for security reasons (%s)', $url));
        }
        $request = $this->crawler->createRequest('GET', $url);
        $response = $this->crawler->sendRequest($request);

        return $this->extract($request, $response);
    }

    /**
     * @return Extractor[]
     */
    public function getMulti(string ...$urls): array
    {
        $requests = array_map(
            function ($url): RequestInterface {
                if (!isValidUrl($url)) {
                    throw new InvalidArgumentException(sprintf(
                        'Access to this URL is blocked for security reasons (%s)',
                        $url
                    ));
                }
                return $this->crawler->createRequest('GET', $url);
            },
            $urls
        );

        $responses = $this->crawler->sendRequests(...$requests);

        $return = [];

        foreach ($responses as $k => $response) {
            /** @phpstan-ignore instanceof.alwaysTrue (defensive check for error handling) */
            if ($response instanceof ResponseInterface) {
                $return[] = $this->extract($requests[$k], $response);
            }
        }

        return $return;
    }

    public function getCrawler(): Crawler
    {
        return $this->crawler;
    }

    public function getExtractorFactory(): ExtractorFactory
    {
        return $this->extractorFactory;
    }

    /**
     * @param array<string, mixed> $settings
     */
    public function setSettings(array $settings): void
    {
        $this->extractorFactory->setSettings($settings);
    }

    private function extract(RequestInterface $request, ResponseInterface $response, bool $redirect = true, int $httpRedirects = 0): Extractor
    {
        $httpRedirectUri = $this->getHttpRedirectUri($request, $response);
        if ($httpRedirectUri !== null) {
            if ($httpRedirects >= self::MAX_HTTP_REDIRECTS) {
                throw new InvalidArgumentException('Maximum number of HTTP redirects exceeded');
            }

            $request = $this->createSafeRequest($httpRedirectUri);
            $response = $this->crawler->sendRequest($request);

            return $this->extract($request, $response, $redirect, $httpRedirects + 1);
        }

        $uri = $this->crawler->getResponseUri($response);
        if ($uri === null) {
            $uri = $request->getUri();
        }

        $extractor = $this->extractorFactory->createExtractor($uri, $request, $response, $this->crawler);

        if (!$redirect || !$this->mustRedirect($extractor)) {
            return $extractor;
        }

        // Magic property access returns mixed, but we know it's ?UriInterface from Redirect detector
        $redirectUri = $extractor->redirect;
        if (!($redirectUri instanceof \Psr\Http\Message\UriInterface)) {
            return $extractor;
        }

        $request = $this->createSafeRequest($redirectUri);
        $response = $this->crawler->sendRequest($request);

        return $this->extract($request, $response, false);
    }

    private function mustRedirect(Extractor $extractor): bool
    {
        if ($extractor->getOEmbed()->all() !== []) {
            return false;
        }

        // Magic property access returns mixed, but we know it's ?UriInterface from Redirect detector
        $redirectUri = $extractor->redirect;
        return $redirectUri instanceof \Psr\Http\Message\UriInterface;
    }

    private function getHttpRedirectUri(RequestInterface $request, ResponseInterface $response): ?UriInterface
    {
        $status = $response->getStatusCode();
        $location = $response->getHeaderLine('Location');

        if ($status < 300 || $status >= 400 || $location === '') {
            return null;
        }

        return resolveUri($request->getUri(), $this->crawler->createUri($location));
    }

    private function createSafeRequest(UriInterface $uri): RequestInterface
    {
        $url = (string) $uri;
        if (!isValidUrl($url)) {
            throw new InvalidArgumentException(sprintf('Access to this URL is blocked for security reasons (%s)', $url));
        }

        return $this->crawler->createRequest('GET', $url);
    }
}
