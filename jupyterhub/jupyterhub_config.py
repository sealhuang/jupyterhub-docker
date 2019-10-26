# vi: set ft=python sts=4 sw=4 ts=4 et:

# JupyterHub configuration
#
## If you update this file, do not forget to delete the `jupyterhub_data` volume before restarting the jupyterhub service:
##
##     docker volume rm jupyterhub_jupyterhub_data
##
## or, if you changed the COMPOSE_PROJECT_NAME to <name>:
##
##    docker volume rm <name>_jupyterhub_data
##

import os
import json
import base64
import urllib

from typing import cast
from traitlets import Unicode, Dict, Bool

from tornado.auth import OAuth2Mixin
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from oauthenticator.oauth2 import OAuthLoginHandler, OAuthenticator

# BenBen Authenticator to use generic OAuth2 with JupyterHub
class BBAuth2Mixin(OAuth2Mixin):
    """Implementation of BenBenAuth."""
    _OAUTH_ACCESS_TOKEN_URL = os.environ.get('OAUTH2_TOKEN_URL', '')
    _OAUTH_AUTHORIZE_URL = os.environ.get('OAUTH2_AUTHORIZE_URL', '')


class BBAuthLoginHandler(OAuthLoginHandler, BBAuth2Mixin):
    pass


# Authenticator config
class BBAuthAuthenticator(OAuthenticator):
    """Implementation of BenBen Authenticator."""
    login_service = Unicode(
        os.environ.get('BBAUTH_NAME', 'OAuth2'),
        config=True
    )

    login_handler = BBAuthLoginHandler

    userdata_url = Unicode(
        os.environ.get('OAUTH2_USERDATA_URL', ''),
        config=True,
        help='Userdata url to get user data login information.'
    )
    token_url = Unicode(
        os.environ.get('OAUTH2_TOKEN_URL', ''),
        config=True,
        help='Access token endpoint URL.'
    )
    extra_params = Dict(
        help="Extra parameters for first POST request"
    ).tag(config=True)

    username_key = Unicode(
        os.environ.get('OAUTH2_USERNAME_KEY', 'username'),
        config=True,
        help="Userdata username key from returned json for USERDATA_URL"
    )
    userdata_params = Dict(
        help="Userdata params to get user data login information"
    ).tag(config=True)

    userdata_method = Unicode(
        os.environ.get('OAUTH2_USERDATA_METHOD', 'GET'),
        config=True,
        help="Userdata method to get user data login information"
    )
    userdata_token_method = Unicode(
        os.environ.get('OAUTH2_USERDATA_REQUEST_TYPE', 'header'),
        config=True,
        help="Method for sending access token in userdata request. Supported methods: header, url. Default: header"
    )

    tls_verify = Bool(
        os.environ.get('OAUTH2_TLS_VERIFY', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable TLS verification on http request"
    )

    basic_auth = Bool(
        os.environ.get('OAUTH2_BASIC_AUTH', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable basic authentication for access token request"
    )

    oauth_callback_url = os.environ.get('OAUTH2_CALLBACK_URL', '')
    
    # your client ID and secret, as provided to you by the OAuth2 service
    client_id = os.environ.get('OAUTH2_CLIENT_ID', '')
    client_secret = os.environ.get('OAUTH2_CLIENT_SECRET', '')

    # authorization code mode
    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        # TODO：configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code'
        )
        params.update(self.extra_params)

        if self.token_url:
            url = self.token_url
        else:
            raise ValueError("Please set the OAUTH2_TOKEN_URL environment variable")

        headers = {
                "Accept": "application/json",
                "User-Agent": "JupyterHub"
        }

        if self.basic_auth:
            b64key = base64.b64encode(
                bytes(
                    "{}:{}".format(self.client_id, self.client_secret),
                    "utf8"
                )
            )
            headers.update({"Authorization": "Basic {}".format(b64key.decode("utf8"))})

        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          validate_cert=self.tls_verify,
                          body=urllib.parse.urlencode(params)
                          )

        resp = await http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']
        refresh_token = resp_json.get('refresh_token', None)
        token_type = resp_json['token_type']
        scope = resp_json.get('scope', '')
        if (isinstance(scope, str)):
            scope = scope.split(' ')

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "{} {}".format(token_type, access_token)
        }
        if self.userdata_url:
            url = url_concat(self.userdata_url, self.userdata_params)
        else:
            raise ValueError("Please set the OAUTH2_USERDATA_URL environment variable")

        if self.userdata_token_method == "url":
            url = url_concat(self.userdata_url, dict(token=access_token))

        req = HTTPRequest(url,
                          method=self.userdata_method,
                          headers=headers,
                          validate_cert=self.tls_verify,
                          )
        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if not resp_json.get(self.username_key):
            self.log.error("OAuth user contains no key %s: %s", self.username_key, resp_json)
            return

        return {
            'name': resp_json.get(self.username_key),
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'oauth_user': resp_json,
                'scope': scope,
            }
        }



## Generic
c.JupyterHub.admin_access = True
# have JupyterLab start by default, or Jupyter Notebook
c.Spawner.default_url = '/lab'
#c.Spawner.default_url = '/tree/home/{username}'

c.JupyterHub.authenticator_class = BBAuthAuthenticator

c.Authenticator.admin_users = { os.environ['ADMIN_USER'] }


## Docker spawner
c.JupyterHub.spawner_class = 'dockerspawner.DockerSpawner'
c.DockerSpawner.image = os.environ['DOCKER_JUPYTER_CONTAINER']
c.DockerSpawner.network_name = os.environ['DOCKER_NETWORK_NAME']
# See https://github.com/jupyterhub/dockerspawner/blob/master/examples/oauth/jupyterhub_config.py
c.JupyterHub.hub_ip = os.environ['HUB_IP']

# user data persistence
# see https://github.com/jupyterhub/dockerspawner#data-persistence-and-dockerspawner
notebook_dir = os.environ.get('DOCKER_NOTEBOOK_DIR') or '/home/jovyan'
c.DockerSpawner.notebook_dir = notebook_dir
c.DockerSpawner.volumes = { 'jupyterhub-user-{username}': notebook_dir }
#c.DockerSpawner.extra_create_kwargs = {
#    'environment': ['JUPYTER_LAB_ENABLE=no'],
#}

# Other stuff
c.Spawner.cpu_limit = 1
c.Spawner.mem_limit = '4G'


## Services
c.JupyterHub.services = [
    {
        'name': 'cull_idle',
        'admin': True,
        'command': 'python /srv/jupyterhub/cull_idle_servers.py --timeout=3600'.split(),
    },
]
