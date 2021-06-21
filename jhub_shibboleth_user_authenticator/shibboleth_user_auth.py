from jupyterhub.handlers import BaseHandler
from jupyterhub.handlers.login import LogoutHandler
from jupyterhub.auth import Authenticator
from tornado.httputil import url_concat
from traitlets import Unicode, List


class ShibbolethUserLoginHandler(BaseHandler):

    async def get(self):
        header_name = self.authenticator.header_name
        remote_user = self.request.headers.get(header_name, '')

        self.log.info("Shibboleth header_name=%s", header_name)
        self.log.info("Shibboleth remote_user=%s", remote_user)
        if remote_user == '':
            self.welcome_page()
        else:
            user = await self.login_user({
                'username': remote_user
            })

            next_url = self.get_next_url(user)
            self.redirect(next_url)

    def welcome_page(self):
        """Present welcome page with login button"""

        next_url = self.get_argument('next', default='')

        if next_url != '':
            target_args = {
                'next': next_url
            }
        else:
            target_args = {}

        html = self.render_template(
            'welcome.html',
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
        self.redirect(self.authenticator.logout_page)


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
        return {
            'name': data.get('username')
        }

