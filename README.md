# jhub_shibboleth_user_authenticator
Shibboleth User Authenticator for JupyterHub


This is an implementation of a Shibboleth User Authenticator. The authenticator needs a 
special proxy (e.g. nginx) which implements the shibboleth authorisation as a service provider,
serving the /Shibboleth.sso/* commands and pass all other addresses to the jupyterhub proxy.

![alt text](https://github.com/ocordes/jhub_shibboleth_user_authenticator/raw/main/demo.png "Demo Login")

This package is the extracting the data from the shibboleth authorisation process and is 
performing the login process in the jupyterhub. 

Shibboleth creates some extra cookies (depending on the configuration), e.g. remote_user . 
Ususally the remote_user is a complete email address 'username @ domain'. Jupyterhub uses 
only a username. In some configurations you can get additional cookie entries e.g. the uid which can
be used in jupyterhub.


## Installation

This package can be installed with `pip` either from a local git repository or from PyPi.

Installation from local git repository:

    cd jhub_shibboleth_user_authenticator
    pip install .

Installation from PyPi:

    pip install jhub_shibboelth_user_authenticator

Alternately, you can add the local project folder must be on your PYTHONPATH.


## Configuration

Usage with a simple jupyterhub configuration:


    # use the shibboleth authentidcator
    c.JupyterHub.authenticator_class = 'jhub_shibboleth_user_authenticator.shibboleth_user_auth.ShibbolethUserAuthenticator

    # use a different cookie entry as the user name , remote_user is the default!
    c.Authenticator.header_name = 'uid'

    # put some extra values in the auth_state for the spawner
    # don't forget to activate c.Authenticator.enable_auth_state = True
    c.Authenticator.auth_state_header_names = ['mail', 'givenname']
