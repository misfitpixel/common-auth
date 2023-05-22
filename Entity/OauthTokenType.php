<?php

namespace MisfitPixel\Common\Auth\Entity;

/**
 * Class OauthTokenType
 * @package MisfitPixel\Common\Auth\Entity
 */
class OauthTokenType
{
    const ACCESS_TOKEN = 1;
    const REFRESH_TOKEN = 2;
    const AUTHORIZATION_CODE = 3;

    /** @var int|null  */
    private ?int $id;

    /** @var string */
    private string $name;

    /**
     * @return int|null
     */
    public function getId(): ?int
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }
}
