<?php
/**
 * Webhook Dispatcher & Remote Avatar Service
 * Author: Junior Backend Developer
 * 
 * Developer Notes:
 * Hey team! I built this service to allow users to register custom webhook endpoints 
 * for event notifications and fetch custom profile avatars from their external URLs.
 * 
 * Security Precautions I Added:
 * - Used filter_var() with FILTER_VALIDATE_URL to make sure the input is a valid URL.
 * - Enforced that the protocol must start with "https://" so traffic is encrypted.
 * - Added a 5-second timeout on cURL so long requests don't hang our server.
 */

class WebhookDispatcher {

    /**
     * Dispatches an event payload to a user-provided webhook endpoint.
     *
     * @param string $webhookUrl The destination URL provided by the user
     * @param array  $payloadData The event data to deliver
     * @return array Status report of the delivery
     */
    public function dispatchNotification(string $webhookUrl, array $payloadData): array {
        // Step 1: Ensure string is a valid URL format
        if (!filter_var($webhookUrl, FILTER_VALIDATE_URL)) {
            return ['success' => false, 'error' => 'Invalid URL syntax'];
        }

        // Step 2: Ensure the scheme is HTTPS for security
        $parsed = parse_url($webhookUrl);
        if (!isset($parsed['scheme']) || strtolower($parsed['scheme']) !== 'https') {
            return ['success' => false, 'error' => 'Only HTTPS endpoints are permitted'];
        }

        if (empty($parsed['host'])) {
            return ['success' => false, 'error' => 'Invalid URL host'];
        }

        $host = trim($parsed['host'], '[]');

        // Validate destination IP address against private/internal subnets (CWE-918)
        $parsedIpv4 = $this->parseIpv4($host);
        if ($parsedIpv4 !== null) {
            $ips = [$parsedIpv4];
        } elseif (filter_var($host, FILTER_VALIDATE_IP)) {
            $ips = [$host];
        } else {
            $ips = [];
            $records = @dns_get_record($host, DNS_A | DNS_AAAA);
            if (is_array($records)) {
                foreach ($records as $record) {
                    if (!empty($record['ip'])) {
                        $ips[] = $record['ip'];
                    }
                    if (!empty($record['ipv6'])) {
                        $ips[] = $record['ipv6'];
                    }
                }
            }
            $byName = @gethostbynamel($host);
            if (is_array($byName)) {
                $ips = array_merge($ips, $byName);
            }
            $ips = array_values(array_unique($ips));

            if (empty($ips)) {
                return ['success' => false, 'error' => 'Could not resolve host'];
            }
        }

        foreach ($ips as $ip) {
            if ($this->isInternalIp($ip)) {
                return ['success' => false, 'error' => 'Requests to private/internal IP addresses are forbidden'];
            }
        }

        // Step 3: Send the HTTP POST request to the remote endpoint
        $ch = curl_init($webhookUrl);
        $jsonData = json_encode($payloadData);

        $curlOptions = [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $jsonData,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Content-Length: ' . strlen($jsonData)
            ],
            CURLOPT_TIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false, // Do not follow redirects to prevent SSRF
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_MAXREDIRS => 3
        ];

        if (!filter_var($host, FILTER_VALIDATE_IP) && $parsedIpv4 === null) {
            $port = $parsed['port'] ?? 443;
            $resolveEntries = [];
            foreach ($ips as $ip) {
                $resolveEntries[] = "{$host}:{$port}:{$ip}";
            }
            $curlOptions[CURLOPT_RESOLVE] = $resolveEntries;
        }

        curl_setopt_array($ch, $curlOptions);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($curlError) {
            return ['success' => false, 'error' => $curlError];
        }

        return [
            'success' => true,
            'status_code' => $httpCode,
            'response' => $response
        ];
    }

    /**
     * Checks if an IP address belongs to private, loopback, or reserved ranges.
     *
     * @param string $ip
     * @return bool True if private or reserved, false if public
     */
    private function isInternalIp(string $ip): bool {
        // Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
        if (preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i', $ip, $matches)) {
            $ip = $matches[1];
        }

        // Check using PHP filter flags for private and reserved ranges
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return true;
        }

        // Additional checks for IPv4 ranges
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $long = (float)sprintf('%u', ip2long($ip));
            $ranges = [
                [(float)sprintf('%u', ip2long('0.0.0.0')), (float)sprintf('%u', ip2long('0.255.255.255'))],       // 0.0.0.0/8
                [(float)sprintf('%u', ip2long('10.0.0.0')), (float)sprintf('%u', ip2long('10.255.255.255'))],     // 10.0.0.0/8 (RFC 1918)
                [(float)sprintf('%u', ip2long('100.64.0.0')), (float)sprintf('%u', ip2long('100.127.255.255'))],  // 100.64.0.0/10 (CGNAT)
                [(float)sprintf('%u', ip2long('127.0.0.0')), (float)sprintf('%u', ip2long('127.255.255.255'))],   // 127.0.0.0/8 (Loopback)
                [(float)sprintf('%u', ip2long('169.254.0.0')), (float)sprintf('%u', ip2long('169.254.255.255'))], // 169.254.0.0/16 (Link-Local / RFC 3927)
                [(float)sprintf('%u', ip2long('172.16.0.0')), (float)sprintf('%u', ip2long('172.31.255.255'))],   // 172.16.0.0/12 (RFC 1918)
                [(float)sprintf('%u', ip2long('192.0.0.0')), (float)sprintf('%u', ip2long('192.0.0.255'))],       // 192.0.0.0/24 (IETF Protocol Assignments)
                [(float)sprintf('%u', ip2long('192.0.2.0')), (float)sprintf('%u', ip2long('192.0.2.255'))],       // 192.0.2.0/24 (TEST-NET-1)
                [(float)sprintf('%u', ip2long('192.168.0.0')), (float)sprintf('%u', ip2long('192.168.255.255'))], // 192.168.0.0/16 (RFC 1918)
                [(float)sprintf('%u', ip2long('198.18.0.0')), (float)sprintf('%u', ip2long('198.19.255.255'))],   // 198.18.0.0/15 (Benchmarking)
                [(float)sprintf('%u', ip2long('198.51.100.0')), (float)sprintf('%u', ip2long('198.51.100.255'))], // 198.51.100.0/24 (TEST-NET-2)
                [(float)sprintf('%u', ip2long('203.0.113.0')), (float)sprintf('%u', ip2long('203.0.113.255'))],   // 203.0.113.0/24 (TEST-NET-3)
                [(float)sprintf('%u', ip2long('224.0.0.0')), (float)sprintf('%u', ip2long('255.255.255.255'))],   // 224.0.0.0/4 (Multicast) and 240.0.0.0/4 (Reserved)
            ];
            foreach ($ranges as [$start, $end]) {
                if ($long >= $start && $long <= $end) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Parses and normalizes an IPv4 address from decimal, octal, hex, or dword format.
     *
     * @param string $host
     * @return string|null Normalized IPv4 address in standard dot-decimal notation, or null if not IPv4
     */
    private function parseIpv4(string $host): ?string {
        $parts = explode('.', $host);
        if (count($parts) > 4) {
            return null;
        }
        $numbers = [];
        foreach ($parts as $p) {
            if (preg_match('/^0x[0-9a-f]+$/i', $p)) {
                $numbers[] = hexdec($p);
            } elseif (preg_match('/^0[0-7]+$/', $p)) {
                $numbers[] = octdec($p);
            } elseif (preg_match('/^\d+$/', $p)) {
                $numbers[] = (int)$p;
            } else {
                return null;
            }
        }
        // Dword (single integer e.g. 2130706433)
        if (count($numbers) === 1) {
            if ($numbers[0] < 0 || $numbers[0] > 4294967295) {
                return null;
            }
            return long2ip($numbers[0]);
        }
        // 2 parts: A.B => A.0.0.B
        if (count($numbers) === 2) {
            if ($numbers[0] > 255 || $numbers[1] > 16777215) {
                return null;
            }
            return long2ip(($numbers[0] << 24) | $numbers[1]);
        }
        // 3 parts: A.B.C => A.B.0.C
        if (count($numbers) === 3) {
            if ($numbers[0] > 255 || $numbers[1] > 255 || $numbers[2] > 65535) {
                return null;
            }
            return long2ip(($numbers[0] << 24) | ($numbers[1] << 16) | $numbers[2]);
        }
        // 4 parts: A.B.C.D
        if (count($numbers) === 4) {
            foreach ($numbers as $n) {
                if ($n < 0 || $n > 255) {
                    return null;
                }
            }
            return implode('.', $numbers);
        }
        return null;
    }
}
