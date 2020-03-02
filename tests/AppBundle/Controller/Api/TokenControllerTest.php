<?php

namespace Tests\AppBundle\Controller\Api;

use AppBundle\Test\ApiTestCase;

class TokenControllerTest extends ApiTestCase
{
    public function testPOSTCreateToken() // Tests to see if we can successfully create an JSON web token
    {
        $this->createUser('weaverryan', 'I<3Pizza'); // Creating a user with a username and password

        $response = $this->client->post('/api/tokens', [ // Making the post request to /api/tokens and sending the users username and password with an auth option that contains the username and password
            'auth' => ['weaverryan', 'I<3Pizza']
        ]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->asserter()->assertResponsePropertyExists(
            $response,
            'token'
        );
    }

    public function testPOSTTokenInvalidCredentials() // Tests to see if we give invalid credentials, we do not get the token because the user is unauthorized
    {
        $this->createUser('weaverryan', 'I<3Pizza');

        $response = $this->client->post('/api/tokens', [
            'auth' => ['weaverryan', 'IH8Pizza']
        ]);
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('application/problem+json', $response->getHeader('Content-Type')[0]);
        $this->asserter()->assertResponsePropertyEquals($response, 'type', 'about:blank');
        $this->asserter()->assertResponsePropertyEquals($response, 'title', 'Unauthorized');
        $this->asserter()->assertResponsePropertyEquals($response, 'detail', 'Invalid credentials.');
    }
}
