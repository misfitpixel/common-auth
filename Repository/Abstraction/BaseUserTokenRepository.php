<?php

namespace MisfitPixel\Common\Auth\Repository\Abstraction;


use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use MisfitPixel\Common\Auth\Entity\Abstraction\BaseUserToken;
use MisfitPixel\Common\Auth\Entity\UserTokenType;
use MisfitPixel\Common\Model\Entity\Status;
use MisfitPixel\Common\Model\Repository\Abstraction\BaseRepository;

/**
 * Class BaseUserTokenRepository
 * @package MisfitPixel\Common\Auth\Repository\Abstraction
 */
abstract class BaseUserTokenRepository extends BaseRepository
    implements AccessTokenRepositoryInterface, RefreshTokenRepositoryInterface, AuthCodeRepositoryInterface
{
    /**
     * @param string $token
     * @return BaseUserToken|null
     */
    public function findOneByToken(string $token): ?BaseUserToken
    {
        return $this->findOneBy([
            'token' => $token
        ]);
    }

    /**
     * @param ClientEntityInterface $clientEntity
     * @param array $scopes
     * @param $userIdentifier
     * @return BaseUserToken
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null): BaseUserToken
    {
        $className = $this->getEntityClassName();
        $token = new $className();
        $token->setUserTokenType($this->getEntityManager()->getRepository($this->getContainer()->getParameter('oauth')['token_type_entity'])->find(UserTokenType::ACCESS_TOKEN))
            ->setClient($clientEntity)
        ;

        /**
         * add scopes to JWT.
         */
        foreach($scopes as $scope) {
            $token->addScope($scope);
        }

        /**
         * for user authorizations (auth_code, password, etc);
         * set a user on the token.
         */
        if($userIdentifier !== null) {
            $token->setUser($this->getEntityManager()->getRepository($this->getContainer()->getParameter('oauth')['user_entity'])->findOneByUsername($userIdentifier));
        }

        return $token;
    }

    /**
     * @param AccessTokenEntityInterface|BaseUserToken $accessTokenEntity
     * @return void
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity)
    {
        $accessTokenEntity->save();
    }

    /**
     * @param $tokenId
     * @return void
     */
    public function revokeAccessToken($tokenId)
    {
        /** @var BaseUserToken $token */
        $token = $this->findOneBy([
            'token' => $tokenId
        ]);

        if(null === $token) {
            return;
        }

        $token->delete(true);
    }

    /**
     * @param $tokenId
     * @return bool
     */
    public function isAccessTokenRevoked($tokenId): bool
    {
        /** @var BaseUserToken $token */
        $token = $this->findOneByToken($tokenId);

        return ($token === null) || $token->getStatusId() !== Status::ACTIVE;
    }

    /**
     * @return BaseUserToken
     */
    public function getNewRefreshToken(): BaseUserToken
    {
        $className = $this->getEntityClassName();
        $token = new $className();
        $token->setUserTokenType($this->getEntityManager()->getRepository($this->getContainer()->getParameter('oauth')['token_type_entity'])->find(UserTokenType::REFRESH_TOKEN));

        return $token;
    }

    /**
     * @param RefreshTokenEntityInterface|BaseUserToken $refreshTokenEntity
     * @return void
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity)
    {
        $refreshTokenEntity->setUser($refreshTokenEntity->getParent()->getUser())
            ->setClient($refreshTokenEntity->getParent()->getClient())
            ->save()
        ;
    }

    /**
     * @param $tokenId
     * @return void
     */
    public function revokeRefreshToken($tokenId)
    {
        $this->revokeAccessToken($tokenId);
    }

    /**
     * @param $tokenId
     * @return bool
     */
    public function isRefreshTokenRevoked($tokenId): bool
    {
        return $this->isAccessTokenRevoked($tokenId);
    }

    /**
     * @return BaseUserToken
     */
    public function getNewAuthCode(): BaseUserToken
    {
        $className = $this->getEntityClassName();
        $token = new $className();
        $token->setUserTokenType($this->getEntityManager()->getRepository($this->getContainer()->getParameter('oauth')['token_type_entity'])->find(UserTokenType::AUTHORIZATION_CODE));

        return $token;
    }

    /**
     * @param AuthCodeEntityInterface|BaseUserToken $authCodeEntity
     * @return void
     */
    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity)
    {
        $authCodeEntity->save();
    }

    /**
     * @param $codeId
     * @return void
     */
    public function revokeAuthCode($codeId)
    {
        $this->revokeAccessToken($codeId);
    }

    /**
     * @param $codeId
     * @return bool
     */
    public function isAuthCodeRevoked($codeId): bool
    {
        return $this->isAccessTokenRevoked($codeId);
    }
}
