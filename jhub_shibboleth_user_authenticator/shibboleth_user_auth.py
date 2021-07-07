from jupyterhub.handlers import BaseHandler
from jupyterhub.handlers.login import LogoutHandler
from jupyterhub.auth import Authenticator
from tornado.httputil import url_concat
from traitlets import Bool, Unicode, List


class ShibbolethUserLoginHandler(BaseHandler):

    async def get(self):
        header_name = self.authenticator.header_name
        remote_user = self.request.headers.get(header_name, '')

        self.log.info("Shibboleth remote_user(%s)=%s", header_name, remote_user)
        if remote_user == '':
            self.login_page()
        else:
            user = await self.login_user({
                'username': remote_user,
                'headers': self.request.headers
            })

            next_url = self.get_next_url(user)
            self.redirect(next_url)


    def login_page(self):
        """Present welcome page with login button"""

        next_url = self.get_argument('next', default='')

        if next_url != '':
            target_args = {
                'next': next_url
            }
        else:
            target_args = {}

        html = self.render_template(
            'login_shibboleth.html',
            sync=True,
            login_service=self.authenticator.login_service,
            authenticator_login_url=url_concat(
                self.authenticator.login_page,
                {
                    'target': url_concat(
                        '/hub/login',
                        target_args
                    )
                }
            ),
        )

        self.finish(html)


class ShibbolethUserLogoutHandler(LogoutHandler):

    """Redirect to Shibboleth logout."""
    #async def handle_logout(self):
    async def render_logout_page(self):
        if self.authenticator.logout_redirect:
            self.redirect(self.authenticator.logout_page)
        else:
            html = self.render_template(
                'logout_shibboleth.html',
                sync=True,
                automatic_redirect=self.authenticator.automatic_redirect,
                authenticator_logout_url=self.authenticator.logout_page
            )

            self.finish(html)



class ShibbolethUserAuthenticator(Authenticator):
    """ Accept the authenticated user name from the REMOTE_USER HTTP header."""

    header_name = Unicode(
        default_value='REMOTE_USER',
        config=True,
        help='HTTP header to inspect for the authenticated username.')

    auth_state_header_names = List(Unicode,
                                   config=True,
                                   default_value=[],
                                   help='List of headers which should be stored as auth_state.')

    login_page = Unicode(
        default_value='/Shibboleth.sso/Login',
        config=True,
        help='Location of login page'
    )

    logout_page = Unicode(
        default_value='/Shibboleth.sso/Logout?return=/',
        config=True,
        help='Location of logout page'
    )

    logout_redirect = Bool(
        default_value=True,
        config=True,
        help='Redirect logout page via direct call'
    )

    automatic_redirect = Bool(
        default_value=False,
        config=True,
        help='Automatically redirect to login page'
    )

    login_service = Unicode(
        default_value='Shibboleth',
        config=True,
        help='Name of the login service'
    )

    def get_handlers(self, app):
        return [
            (r'/login', ShibbolethUserLoginHandler),
            (r'/logout', ShibbolethUserLogoutHandler),
        ]

    async def authenticate(self, handler, data):
        """ authenticate extracts the data useful for the session

        data includes also the shibboleth response header with some additionals keys to extract and
        store in auth_state
        """
        headers = data.get('headers')
        auth_state_data = {key: headers.get(key) for key in self.auth_state_header_names}

        return {
            'name': data.get('username'),
            'auth_state': auth_state_data
        }

