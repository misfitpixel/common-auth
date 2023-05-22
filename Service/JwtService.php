<?php

namespace MisfitPixel\Common\Auth\Service;


use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Class JwtService
 * @package MisfitPixel\Common\Auth\Service
 */
class JwtService
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
            InMemory::plainText('')
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
     * @param string $identifier
     * @return Token
     */
    public function decode(string $identifier): Token
    {
        try {
            $token = $this->jwtConfiguration->parser()->parse($identifier);

        } catch(\Exception $e) {
            $token = null;
        }

        return $token;
    }
}
