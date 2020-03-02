<?php

namespace AppBundle\Controller\Api;

use AppBundle\Controller\BaseController;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

class TokenController extends BaseController
{
    /**
     * @Route("/api/tokens")
     * @Method("POST")
     */
    public function newTokenAction(Request $request)
    {
        $user = $this->getDoctrine() // Finds a user via their username. We are using the basic HTTP username string to search the database, in order to get that we are using the $request objects getUser() method to get it
            ->getRepository('AppBundle:User')
            ->findOneBy(['username' => $request->getUser()]);

        if (!$user) { // If we cannot find the user
            throw $this->createNotFoundException(); // Throw a 404 not found exception
        }

        $isValid = $this->get('security.password_encoder') // Getting the encoded password of the user
            ->isPasswordValid($user, $request->getPassword()); // Checks to see if the password for the user is valid by passing the user object and their basic HTTP password string

        if (!$isValid) { // if the password is not valid throw a bad credentials exception
            throw new BadCredentialsException();
        }

        $token = $this->get('lexik_jwt_authentication.encoder') // Generating the JSON web token
            ->encode([ // This is the array of information that we want to store in the token
                'username' => $user->getUsername(),
                'exp' => time() + 3600 // 1 hour expiration
            ]);

        return new JsonResponse(['token' => $token]); // Since this is a string, I am returning a new JsonResponse with a token feild set to the variable $token which we defined above
    }
}