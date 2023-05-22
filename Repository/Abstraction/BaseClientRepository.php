<?php

namespace MisfitPixel\Common\Auth\Repository\Abstraction;


use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use MisfitPixel\Common\Auth\Entity\Abstraction\Client;
use MisfitPixel\Common\Model\Entity\Status;
use MisfitPixel\Common\Model\Repository\Abstraction\BaseRepository;

/**
 * Class BaseClientRepository
 * @package MisfitPixel\Common\Auth\Repository\Abstraction
 */
abstract class BaseClientRepository extends BaseRepository implements ClientRepositoryInterface
{
    /**
     * @param $clientIdentifier
     * @return Client|null
     */
    public function getClientEntity($clientIdentifier): ?Client
    {
        return $this->findOneBy([
            'clientId' => $clientIdentifier,
            'statusId' => Status::ACTIVE
        ]);
    }

    /**
     * @param $clientIdentifier
     * @param $clientSecret
     * @param $grantType
     * @return bool
     */
    public function validateClient($clientIdentifier, $clientSecret, $grantType): bool
    {
        $client = $this->getClientEntity($clientIdentifier);

        if($client === null) {
            return false;
        }

        return $client->getSecret() === $clientSecret;
    }
}
