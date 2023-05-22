<?php

namespace MisfitPixel\Common\Auth\Controller\Abstraction;


use Doctrine\Persistence\ManagerRegistry;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Grant\PasswordGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use MisfitPixel\Common\Auth\Entity\User;
use MisfitPixel\Common\Exception;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class BaseOauthController
 * @package MisfitPixel\Common\Auth\Controller\Abstraction
 */
abstract class BaseOauthController extends AbstractController
{
    /** @var ClientRepositoryInterface  */
    private ClientRepositoryInterface $clientRepository;

    /** @var ScopeRepositoryInterface  */
    private ScopeRepositoryInterface $scopeRepository;

    /** @var AccessTokenRepositoryInterface  */
    private AccessTokenRepositoryInterface $accessTokenRepository;

    /** @var AuthCodeRepositoryInterface  */
    private AuthCodeRepositoryInterface $authCodeRepository;

    /** @var RefreshTokenRepositoryInterface  */
    private RefreshTokenRepositoryInterface $refreshTokenRepository;

    /** @var UserRepositoryInterface  */
    private UserRepositoryInterface $userRepository;

    /** @var string  */
    private string $privateKey;

    /** @var string  */
    private string $encryptionKey;

    /**
     * @param ContainerInterface $container
     * @param ManagerRegistry $manager
     */
    public function __construct(ContainerInterface $container, ManagerRegistry $manager)
    {
        /** @var ClientRepositoryInterface $clientRepository */
        $clientRepository = $manager->getRepository($container->getParameter('oauth')['client_entity']);

        /** @var ScopeRepositoryInterface $scopeRepository */
        $scopeRepository = $manager->getRepository($container->getParameter('oauth')['scope_entity']);

        /** @var AccessTokenRepositoryInterface|RefreshTokenRepositoryInterface|AuthCodeRepositoryInterface $accessTokenRepository */
        $accessTokenRepository = $manager->getRepository($container->getParameter('oauth')['token_entity']);

        /** @var UserRepositoryInterface $userRepository */
        $userRepository = $manager->getRepository($container->getParameter('oauth')['user_entity']);

        $this->clientRepository = $clientRepository;
        $this->scopeRepository = $scopeRepository;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->authCodeRepository = $this->accessTokenRepository;
        $this->refreshTokenRepository = $this->accessTokenRepository;
        $this->userRepository = $userRepository;

        $this->privateKey = sprintf("file://%s", $container->getParameter('oauth')['private_key']);
        $this->encryptionKey = $container->getParameter('oauth')['encryption_key'];
    }

    /**
     * @param Request $request
     * @return Response
     */
    abstract function signin(Request $request): Response;

    /**
     * @param Request $request
     * @return Response
     * @throws \Exception
     */
    public function authorize(Request $request): Response
    {
        $server = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $this->privateKey,
            $this->encryptionKey
        );

        $grant = new AuthCodeGrant(
            $this->authCodeRepository,
            $this->refreshTokenRepository,
            new \DateInterval('PT10M')
        );

        $grant->setRefreshTokenTTL(new \DateInterval('P1M'));

        $server->enableGrantType(
            $grant,
            new \DateInterval('PT1H')
        );

        try {
            $authRequest = $server->validateAuthorizationRequest($this->convertToPsr($request));

            /** @var User $user */
            $user = $this->userRepository->findOneByUsername($request->request->get('username'));

            if($user === null) {
                throw new Exception\UnauthorizedException();
            }

            if(!$user->isPassword($request->request->get('password'))) {
                throw new Exception\UnauthorizedException();
            }

            $authRequest->setUser($user);

            /**
             * TODO: confirm the user has "approved" the scopes;
             * TODO: will likely happen from frontend and this will always be true.
             */
            $authRequest->setAuthorizationApproved(true);

            return $this->convertFromPsr(
                $server->completeAuthorizationRequest($authRequest, $this->convertToPsr(new Response()))
            );

        } catch(OAuthServerException $e) {
            return $this->redirectToRoute('oauth_signin', [
                'response_type' => $request->query->get('response_type'),
                'client_id' => $request->query->get('client_id'),
                'redirect_uri' => urlencode($request->query->get('redirect_uri')),
                'error_message' => 'OAuth authorization failed. Please check URL parameters and try again.'
            ]);

        } catch(\Exception $e) {
            return $this->redirectToRoute('oauth_signin', [
                'response_type' => $request->query->get('response_type'),
                'client_id' => $request->query->get('client_id'),
                'redirect_uri' => urlencode($request->query->get('redirect_uri')),
                'error_message' => $e->getMessage()
            ]);
        }
    }

    /**
     * @param Request $request
     * @return Response
     * @throws \Exception
     */
    public function token(Request $request): Response
    {
        $server = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $this->privateKey,
            $this->encryptionKey
        );

        $grant = new AuthCodeGrant(
            $this->authCodeRepository,
            $this->refreshTokenRepository,
            new \DateInterval('PT10M')
        );

        $grant->setRefreshTokenTTL(new \DateInterval('P1M'));

        $server->enableGrantType(
            $grant,
            new \DateInterval('PT1H')
        );

        $server->enableGrantType(
            new ClientCredentialsGrant(),
            new \DateInterval('PT1H')
        );

        $grant = new RefreshTokenGrant($this->refreshTokenRepository);
        $grant->setRefreshTokenTTL(new \DateInterval('P1M'));

        $server->enableGrantType(
            $grant,
            new \DateInterval('PT1H')
        );

        $grant = new PasswordGrant($this->userRepository, $this->refreshTokenRepository);
        $grant->setRefreshTokenTTL(new \DateInterval('P1M'));

        $server->enableGrantType(
            $grant,
            new \DateInterval('PT1H')
        );

        try {
            return $this->convertFromPsr(
                $server->respondToAccessTokenRequest($this->convertToPsr($request), $this->convertToPsr(new Response()))
            );

        } catch(OAuthServerException $e) {
            throw new Exception\OauthAuthorizationException(
                sprintf("OAuth error: please check your request, or review our OAuth documentation at %s", $this->getParameter('spoonity.common.documentation.url')),
                $e->getHint()
            );

        } catch(\Exception $e) {
            throw new Exception\UnknownErrorException();
        }
    }

    /**
     * @param Request|Response $symfonyObject
     * @return ServerRequestInterface|ResponseInterface
     * @throws \Exception
     */
    private function convertToPsr($symfonyObject)
    {
        $psr17Factory = new Psr17Factory();
        $psrHttpFactory = new PsrHttpFactory($psr17Factory, $psr17Factory, $psr17Factory, $psr17Factory);

        switch(true) {
            case $symfonyObject instanceof Request:
                return $psrHttpFactory->createRequest($symfonyObject);

            case $symfonyObject instanceof Response:
                return $psrHttpFactory->createResponse($symfonyObject);

            default:
                throw new \Exception('Provided object must be one of Symfony\Component\HttpFoundation\Request or Symfony\Component\HttpFoundation\Response');
        }
    }

    /**
     * @param $psrObject
     * @return Request|Response|\Symfony\Component\HttpFoundation\StreamedResponse
     * @throws \Exception
     */
    private function convertFromPsr($psrObject)
    {
        $httpFoundationFactory = new HttpFoundationFactory();

        switch(true) {
            case $psrObject instanceof ServerRequestInterface:
                return $httpFoundationFactory->createRequest($psrObject);

            case $psrObject instanceof ResponseInterface:
                return $httpFoundationFactory->createResponse($psrObject);

            default:
                throw new \Exception('Provided object must be one of Symfony\Component\HttpFoundation\Request or Symfony\Component\HttpFoundation\Response');
        }
    }
}
