<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** Optional staging instrumentation. Register after session/auth middleware. */
final class NaviTrace
{
    public function handle(Request $request, Closure $next): Response
    {
        $nonce = $request->header('X-Navi-Request-ID', '');
        $key = (string) config('navi.trace_key', '');
        $digest = (string) config('navi.source_digest', '');
        if (!preg_match('/^[0-9a-f]{32}$/D', $nonce) || strlen($key) < 32 ||
            !preg_match('/^[0-9a-f]{64}$/D', $digest)) {
            return $next($request);
        }
        // State belongs to this request, including under Octane/worker reuse.
        $request->attributes->set('navi.operations', []);
        $request->attributes->set('navi.truncated', false);
        $response = $next($request);
        $data = [
            'version' => 2, 'request_id' => $nonce, 'method' => $request->getMethod(),
            'path' => parse_url($request->getRequestUri(), PHP_URL_PATH),
            'source_digest' => $digest,
            'truncated' => $request->attributes->get('navi.truncated', false),
            'operations' => $request->attributes->get('navi.operations', []),
        ];
        $encoded = self::encode($data);
        if (strlen($encoded) > 6000) {
            $data['operations'] = [];
            $data['truncated'] = true;
            $encoded = self::encode($data);
        }
        $response->headers->set('X-Navi-Trace', $encoded);
        $response->headers->set('X-Navi-Trace-Signature', hash_hmac('sha256', $encoded, $key));
        $response->headers->set('Cache-Control', 'private, no-store');
        return $response;
    }

    /** Record at the sink, only after the specified input reaches its argument.
     * Never copy operation IDs, locations or input labels from request headers.
     * A controller-entry marker cannot establish operation/input attribution.
     */
    public static function record(Request $request, string $operationId, string $file,
        int $line, string $cwe, array $inputs): void
    {
        if (!$request->attributes->has('navi.operations')) return;
        $operations = $request->attributes->get('navi.operations');
        $operation = ['operation_id' => $operationId, 'file' => $file, 'line' => $line,
                      'cwe' => $cwe, 'inputs' => $inputs];
        if (in_array($operation, $operations, true)) return;
        if (count($operations) >= 32) {
            $request->attributes->set('navi.truncated', true);
            return;
        }
        $operations[] = $operation;
        $request->attributes->set('navi.operations', $operations);
    }

    private static function encode(array $data): string
    {
        return rtrim(strtr(base64_encode(json_encode($data, JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
    }
}
