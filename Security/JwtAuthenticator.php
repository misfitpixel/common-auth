<?php

namespace MisfitPixel\Common\Auth\Security;


use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use MisfitPixel\Common\Auth\Entity\User;
use MisfitPixel\Common\Exception;
use MisfitPixel\Common\Auth\Entity\Abstraction\BaseUserToken;
use MisfitPixel\Common\Model\Entity\Status;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Class JwtAuthenticator
 * @package MisfitPixel\Common\Auth\Security
 */
class JwtAuthenticator extends AbstractAuthenticator
{
    /** @var ContainerInterface  */
    private ContainerInterface $container;

    /** @var Configuration  */
    private Configuration $jwtConfiguration;

    /**
     * @param ContainerInterface $container
     * @throws \Exception
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;

        /**
         * prepare config for validating signed JWT with public key.
         */
        $this->jwtConfiguration = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::base64Encoded($this->container->getParameter('oauth')['encryption_key'])
        );

        $this->jwtConfiguration->setValidationConstraints(
            new StrictValidAt(new SystemClock(new \DateTimeZone(\date_default_timezone_get()))),
            new SignedWith(
                new Sha256(),
                InMemory::file(sprintf("file://%s", $this->container->getParameter('oauth')['public_key']))
            )
        );
    }

    /**
     * @param Request $request
     * @return bool|null
     */
    public function supports(Request $request): ?bool
    {
        $routeParams = $request->attributes->get('_route_params');

        return isset($routeParams['oauth_scopes']) && !empty($routeParams['oauth_scopes']);
    }

    /**
     * @param Request $request
     * @return Passport
     */
    public function authenticate(Request $request): Passport
    {
        $token = trim(str_replace('Bearer', '', $request->headers->get('Authorization')));

        return new SelfValidatingPassport(
            new UserBadge($token, function($identifier) use ($request) {
                /**
                 * decode JWT from identifier.
                 */
                $decodedJwt = $this->jwtConfiguration->parser()->parse($identifier);
                $routeParams = $request->attributes->get('_route_params');
                $routeScopes = $routeParams['oauth_scopes'] ?? [];

                /**
                 * compare scopes on route with scopes on token.
                 */
                foreach($decodedJwt->claims()->get('scopes') as $scope) {
                    /**
                     * if root scope, end process.
                     */
                    if($scope === 'root') {
                        $routeScopes = [];

                        break;
                    }

                    $key = array_search($scope, $routeScopes);

                    /**
                     * mark scope as claimed.
                     */
                    if($key !== false) {
                        unset($routeScopes[$key]);
                    }
                }

                /**
                 * if user does not possess all scopes, then fail authentication.
                 * throw 403 forbidden instead of unauthorized.
                 */
                if(sizeof($routeScopes) > 0) {
                    throw new Exception\MissingScopesException($routeScopes);
                }

                /** @var BaseUserToken $userToken */
                $userToken = $this->container->get('doctrine')
                    ->getRepository($this->container->getParameter('oauth')['token_entity'])
                    ->findOneByToken($decodedJwt->claims()->get('jti'))
                ;

                /**
                 * confirm validity of token.
                 * TODO: may not need to do time check since $this->jwtConfiguration handles that.
                 */
                if(
                    $userToken->getStatusId() !== Status::ACTIVE ||
                    $userToken->getDateExpired()->getTimestamp() < time()
                ) {
                    throw new Exception\UnauthorizedException();
                }

                /**
                 * match user to username encoded in JWT.
                 */
                return $userToken->getUser();
            })
        );
    }

    /**
     * @param Request $request
     * @param TokenInterface $token
     * @param string $firewallName
     * @return Response|null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    /**
     * @param Request $request
     * @param AuthenticationException $exception
     * @return Response|null
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        throw new Exception\UnauthorizedException();
    }

}
