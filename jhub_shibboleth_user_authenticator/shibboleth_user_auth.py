
import os
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import Unicode



class ShibbolethUserLoginHandler(BaseHandler):

    def get(self):
        header_name = self.authenticator.header_name
        remote_user = self.request.headers.get(header_name, "")

        if remote_user == "":
            self.welcome_page()
        else:
            user = self.user_from_username(remote_user)
            self.set_login_cookie(user)

            next_url = self.get_next_url(user)
            self.redirect(next_url)

            self.statsd.incr('login.request')

    def welcome_page(self):
        """Present welcome page with login button"""

        html = self.render_template(
            'welcome.html',
            next=url_escape(self.get_argument('next', default='')),
            custom_html=self.authenticator.custom_html,
            login_url=self.settings['login_url'],
            login_service='Shibboleth',
            authenticator_login_url=url_concat(
                self.authenticator.login_url(self.hub.base_url),
                {'target': self.get_argument('next', '')},
            ),
        )

        self.finish(html)




class ShibbolethUserAuthenticator(Authenticator):
    """
    Accept the authenticated user name from the REMOTE_USER HTTP header.
    """
    header_name = Unicode(
        default_value='REMOTE_USER',
        config=True,
        help="""HTTP header to inspect for the authenticated username.""")

    def get_handlers(self, app):
        return [
            (r'/login', ShibbolethUserLoginHandler),
        ]

    def login_url(self, base_url):
        return self.domain + '/Shibboleth.sso/Login

    def logout_url(self, base_url):
        return self.domain + '/Shibboleth.sso/Logout?return=/'


    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()


class ShibbolethUserLocalAuthenticator(LocalAuthenticator):
    """
    Accept the authenticated user name from the REMOTE_USER HTTP header.
    Derived from LocalAuthenticator for use of features such as adding
    local accounts through the admin interface.
    """
    header_name = Unicode(
        default_value='REMOTE_USER',
        config=True,
        help="""HTTP header to inspect for the authenticated username.""")

    def get_handlers(self, app):
        return [
            (r'/login', ShibbolethUserLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()
