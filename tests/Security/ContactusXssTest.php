<?php

declare(strict_types=1);

namespace Tests\Security;

/**
 * XSS tests for contactus mutation.
 * Tests name, email, and message fields for XSS vulnerabilities.
 */
class ContactusXssTest extends BaseSecurityTest
{
    /**
     * Test XSS in name field of contactus mutation.
     *
     * @dataProvider xssPayloadsProvider
     */
    public function testContactusNameXss(string $payload): void
    {
        $query = '
            mutation Contactus {
                contactus(name: "' . $payload . '", email: "test@example.com", message: "Test message") {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    affectedRows {
                        msgid
                        email
                        name
                        message
                        ip
                        createdat
                    }
                }
            }
        ';

        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        $data = $this->parseGraphQLResponse($response);
        
        // Check if XSS payload is returned unescaped in response
        if (isset($data['data']['contactus']['affectedRows'])) {
            foreach ($data['data']['contactus']['affectedRows'] as $row) {
                if (isset($row['name']) && $this->containsUnescapedXss($row['name'], $payload)) {
                    $this->fail('XSS payload returned unescaped in name field: ' . $payload);
                }
            }
        }
    }

    /**
     * Test XSS in email field of contactus mutation.
     *
     * @dataProvider xssPayloadsProvider
     */
    public function testContactusEmailXss(string $payload): void
    {
        $query = '
            mutation Contactus {
                contactus(name: "Test User", email: "' . $payload . '", message: "Test message") {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    affectedRows {
                        msgid
                        email
                        name
                        message
                        ip
                        createdat
                    }
                }
            }
        ';

        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        $data = $this->parseGraphQLResponse($response);
        
        // Check if XSS payload is returned unescaped in response
        if (isset($data['data']['contactus']['affectedRows'])) {
            foreach ($data['data']['contactus']['affectedRows'] as $row) {
                if (isset($row['email']) && $this->containsUnescapedXss($row['email'], $payload)) {
                    $this->fail('XSS payload returned unescaped in email field: ' . $payload);
                }
            }
        }
    }

    /**
     * Test XSS in message field of contactus mutation.
     *
     * @dataProvider xssPayloadsProvider
     */
    public function testContactusMessageXss(string $payload): void
    {
        $query = '
            mutation Contactus {
                contactus(name: "Test User", email: "test@example.com", message: "' . $payload . '") {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    affectedRows {
                        msgid
                        email
                        name
                        message
                        ip
                        createdat
                    }
                }
            }
        ';

        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        $data = $this->parseGraphQLResponse($response);
        
        // Check if XSS payload is returned unescaped in response
        if (isset($data['data']['contactus']['affectedRows'])) {
            foreach ($data['data']['contactus']['affectedRows'] as $row) {
                if (isset($row['message']) && $this->containsUnescapedXss($row['message'], $payload)) {
                    $this->fail('XSS payload returned unescaped in message field: ' . $payload);
                }
            }
        }
    }

    /**
     * Test XSS in all fields simultaneously.
     *
     * @dataProvider xssPayloadsProvider
     */
    public function testContactusAllFieldsXss(string $payload): void
    {
        $query = '
            mutation Contactus {
                contactus(name: "' . $payload . '", email: "' . $payload . '", message: "' . $payload . '") {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    affectedRows {
                        msgid
                        email
                        name
                        message
                        ip
                        createdat
                    }
                }
            }
        ';

        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        $data = $this->parseGraphQLResponse($response);
        
        // Check all fields for unescaped XSS
        if (isset($data['data']['contactus']['affectedRows'])) {
            foreach ($data['data']['contactus']['affectedRows'] as $row) {
                foreach (['name', 'email', 'message'] as $field) {
                    if (isset($row[$field]) && $this->containsUnescapedXss($row[$field], $payload)) {
                        $this->fail('XSS payload returned unescaped in ' . $field . ' field: ' . $payload);
                    }
                }
            }
        }
    }

    /**
     * Test JavaScript URI XSS in email field.
     */
    public function testContactusJavaScriptUriXss(): void
    {
        $javascriptUris = [
            'javascript:alert("XSS")',
            'JaVaScRiPt:alert("XSS")',
            'javascript://alert("XSS")',
            'javascript:alert(document.cookie)',
        ];

        foreach ($javascriptUris as $payload) {
            $query = '
                mutation Contactus {
                    contactus(name: "Test User", email: "' . $payload . '", message: "Test message") {
                        meta {
                            status
                            RequestId
                            ResponseCode
                            ResponseMessage
                        }
                        affectedRows {
                            msgid
                            email
                            name
                            message
                            ip
                            createdat
                        }
                    }
                }
            ';

            $request = $this->createGraphQLRequest($query);
            $response = $this->executeGraphQLRequest($request);
            
            $this->assertNoSqlErrors($response);
            $this->assertProperErrorHandling($response);
            
            $data = $this->parseGraphQLResponse($response);
            
            // Check if JavaScript URI is returned unescaped
            if (isset($data['data']['contactus']['affectedRows'])) {
                foreach ($data['data']['contactus']['affectedRows'] as $row) {
                    if (isset($row['email']) && stripos($row['email'], 'javascript:') !== false) {
                        $this->fail('JavaScript URI returned unescaped in email field: ' . $payload);
                    }
                }
            }
        }
    }

    /**
     * Test that valid contactus submission works (sanity check).
     */
    public function testValidContactusSubmission(): void
    {
        $query = '
            mutation Contactus {
                contactus(name: "Valid User", email: "valid@example.com", message: "Valid message without XSS") {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    affectedRows {
                        msgid
                        email
                        name
                        message
                        ip
                        createdat
                    }
                }
            }
        ';

        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
    }

    /**
     * Check if response contains unescaped XSS payload.
     *
     * @param string $responseValue Value from response
     * @param string $originalPayload Original XSS payload sent
     * @return bool
     */
    private function containsUnescapedXss(string $responseValue, string $originalPayload): bool
    {
        // Decode HTML entities to check if payload is escaped
        $decoded = html_entity_decode($responseValue, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        // Check if dangerous tags/attributes are present
        $dangerousPatterns = [
            '/<script[^>]*>/i',
            '/on\w+\s*=/i',
            '/javascript:/i',
            '/data:text\/html/i',
            '/<svg[^>]*>/i',
            '/<iframe[^>]*>/i',
            '/<object[^>]*>/i',
            '/<embed[^>]*>/i',
            '/<applet[^>]*>/i',
        ];

        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $decoded)) {
                return true;
            }
        }

        // Check if original payload appears unescaped
        $escapedPayload = htmlspecialchars($originalPayload, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        if ($responseValue === $originalPayload && $responseValue !== $escapedPayload) {
            return true;
        }

        return false;
    }

    /**
     * Data provider for XSS payloads.
     *
     * @return array
     */
    public function xssPayloadsProvider(): array
    {
        return array_map(
            fn($payload) => [$payload],
            $this->getXssPayloads()
        );
    }
}