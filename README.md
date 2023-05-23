# common-auth

Authentication and authorization systems for PHP projects based on the [Symfony](https://www.symfony.com/) framework.

### Initialization

This library functions as a support suite for the native Symfony [security bundle](https://symfony.com/doc/current/security.html).

In order to initialize the packages for this system, they need to be registered in the _config/packages/security.yaml_ file:
```yaml
security:
    enable_authenticator_manager: true
    # https://symfony.com/doc/current/security.html#registering-the-user-hashing-passwords
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface: 'auto'
    # https://symfony.com/doc/current/security.html#loading-the-user-the-user-provider
    providers:
        user_provider:
            id: MisfitPixel\Common\Auth\Security\UserProvider

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            lazy: false
            provider: user_provider
            custom_authenticators:
                - MisfitPixel\Common\Auth\Security\JwtAuthenticator
...
```

Next, the Symfony password hasher should be register as a service in _config/services.yaml_.
```yaml
parameters:
...
services:
...
  security.user_password_hasher:
    class: Symfony\Component\PasswordHasher\Hasher\UserPasswordHasher
    public: true
...
```

This library exposes three classes for interacting with the Symfony security bundle: _MisfitPixel\Common\Auth\Security\UserProvider_, for passing the _MisfitPixel\Common\Auth\Entity\User_ class, which contains the authenticated user's details, and _MisfitPixel\Common\Auth\Security\JwtAuthenticator_, which translates a JWT Authorization header into that user.

### Routes

In order to enable authentication for routes, each route must specify an `oauth_scopes` array in the route definition.

```yaml
...
user_list:
  path: /
  controller: App\Controller\UserController::list
  defaults:
    oauth_scopes: [ user.view ] # enables authentication
  methods: [ GET, OPTIONS ]
...
```

The _JwtAuthenticator_ will automatically compare the scopes encoded in the JWT with the scopes required for the route, and throw the appropriate exception if necessary.

### Interacting with the User
Assuming the scope requirements are met, controllers will provide access to a `$this->getUser()` method, which will return a _MisfitPixel\Common\Auth\Entity\User_.  This class will expose important information about the authenticated user like their personal details and ID.
