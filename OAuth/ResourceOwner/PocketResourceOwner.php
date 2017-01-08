<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware.Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use Buzz\Message\RequestInterface as HttpRequestInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * FacebookResourceOwner.
 *
 * @author Stefan Adolf <stadolf@gmail.com>
 */
class PocketResourceOwner extends GenericOAuth2ResourceOwner
{
    /**
     * {@inheritdoc}
     */
    protected $paths = array(
        'identifier' => 'id',
        'nickname' => 'name',
        'firstname' => 'first_name',
        'lastname' => 'last_name',
        'realname' => 'name',
        'email' => 'email',
    );

    /**
     * {@inheritdoc}
     */
    public function getUserInformation(array $accessToken, array $extraParameters = array())
    {
        if ($this->options['appsecret_proof']) {
            $extraParameters['appsecret_proof'] = hash_hmac('sha256', $accessToken['access_token'], $this->options['client_secret']);
        }

        return parent::getUserInformation($accessToken, $extraParameters);
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationUrl($redirectUri, array $extraParameters = array())
    {
        if ($this->options['csrf']) {
            if (null === $this->state) {
                $this->state = $this->generateNonce();
            }

            $this->storage->save($this, $this->state, 'csrf_state');
        }

        $parameters = array_merge(array(
            'consumer_key' => $this->options['client_id'],
            'redirect_uri' => $redirectUri,
            'state' => $this->state ? urlencode($this->state) : null,
        ), $extraParameters);

        return $this->normalizeUrl($this->options['authorization_url'], $parameters);
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken(Request $request, $redirectUri, array $extraParameters = array())
    {
        $parameters = array();
        if ($request->query->has('fb_source')) {
            $parameters['fb_source'] = $request->query->get('fb_source');
        }

        if ($request->query->has('fb_appcenter')) {
            $parameters['fb_appcenter'] = $request->query->get('fb_appcenter');
        }

        return parent::getAccessToken($request, $this->normalizeUrl($redirectUri, $parameters), $extraParameters);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeToken($token)
    {
        $parameters = array(
            'client_id' => $this->options['client_id'],
            'client_secret' => $this->options['client_secret'],
        );

        $response = $this->httpRequest($this->normalizeUrl($this->options['revoke_token_url'], array('access_token' => $token)), $parameters, array(), HttpRequestInterface::METHOD_DELETE);

        return 200 === $response->getStatusCode();
    }

    protected function doGetTokenRequest($url, array $parameters = array())
    {
        return $this->httpRequest($url, http_build_query($parameters, '', '&'), array(), HttpRequestInterface::METHOD_POST);
    }

    /**
     * {@inheritdoc}
     */
    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults(array(
            'authorization_url' => 'https://getpocket.com/v3/oauth/request',
            'access_token_url' => 'https://getpocket.com/v3/oauth/authorize',
            'revoke_token_url' => 'https://graph.facebook.com/v2.7/me/permissions',
            //'infos_url' => 'https://graph.facebook.com/v2.7/me?fields=first_name,last_name,name,email',
        ));
    }
}
