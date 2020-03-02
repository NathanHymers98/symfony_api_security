<?php

namespace AppBundle\Security;

use AppBundle\Api\ApiProblem;
use AppBundle\Api\ResponseFactory;
use Doctrine\ORM\EntityManager;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\AuthorizationHeaderTokenExtractor;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class JwtTokenAuthenticator extends AbstractGuardAuthenticator // Every authenticator extends this class
{
    private $jwtEncoder;
    private $em;
    private $responseFactory;

    public function __construct(JWTEncoderInterface $jwtEncoder, EntityManager $em, ResponseFactory $responseFactory)
    {
        $this->jwtEncoder = $jwtEncoder;
        $this->em = $em;
        $this->responseFactory = $responseFactory;
    }

    public function getCredentials(Request $request) // Reads the authorization header and gets the token if one is being passed
    {
        $extractor = new AuthorizationHeaderTokenExtractor( // Creating the extractor which will extract the token
            'Bearer', // The prefix before the actual token
            'Authorization' // The header to look on because it will contain the token
        );

        $token = $extractor->extract($request); // Getting the token via the extractor

        if (!$token) { // If the token does not exist, then return nothing. This will cause authentication to stop not fail
            return;
        }

        return $token; // if the token does exist, then return it
    }

    public function getUser($credentials, UserProviderInterface $userProvider) // next this method will be called, and it gets passed the users credentials as an argument. It's job is to find the user the token relates to
    {
        $data = $this->jwtEncoder->decode($credentials); // Using the jwtEncoder to decode the token, so that we can get the username for the user

        if ($data === false) { // if the token doesn't exist
            throw new CustomUserMessageAuthenticationException('Invalid Token'); // throw a new exception
        }

        $username = $data['username']; // if the token does exist, get the username from the decoded token

        return $this->em // return the user object that was found in the database using the username we just got from the decoded token
            ->getRepository('AppBundle:User')
            ->findOneBy(['username' => $username]);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $apiProblem = new ApiProblem(401);
        // you could translate this
        $apiProblem->set('detail', $exception->getMessageKey());

        return $this->responseFactory->createResponse($apiProblem);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // do nothing - let the controller be called
    }

    public function supportsRememberMe()
    {
        return false;
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        // called when authentication info is missing from a
        // request that requires it

        $apiProblem = new ApiProblem(401);
        // you could translate this
        $message = $authException ? $authException->getMessageKey() : 'Missing credentials';
        $apiProblem->set('detail', $message);

        return $this->responseFactory->createResponse($apiProblem);
    }
}
