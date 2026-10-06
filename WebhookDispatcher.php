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

        // Step 3: Send the HTTP POST request to the remote endpoint
        $ch = curl_init($webhookUrl);
        $jsonData = json_encode($payloadData);

        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $jsonData,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Content-Length: ' . strlen($jsonData)
            ],
            CURLOPT_TIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => true, // Automatically follow any 301/302 redirects!
            CURLOPT_MAXREDIRS => 3
        ]);

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
}
