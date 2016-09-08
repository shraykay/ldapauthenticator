import ldap3
import re

from jupyterhub.auth import Authenticator
from tornado import gen
from traitlets import Unicode, Int, Bool, Union, List


class LDAPAuthenticator(Authenticator):
    server_address = Unicode(
        config=True,
        help='Address of LDAP server to contact'
    )
    server_port = Int(
        config=True,
        help='Port on which to contact LDAP server',
    )

    def _server_port_default(self):
        if self.use_ssl:
            return 636  # default SSL port for LDAP
        else:
            return 389  # default plaintext port for LDAP

    use_ssl = Bool(
        True,
        config=True,
        help='Use SSL to encrypt connection to LDAP server'
    )

    bind_dn_template = Unicode(
        config=True,
        help="""
        Template from which to construct the full dn
        when authenticating to LDAP. {username} is replaced
        with the actual username.

        Example:

            uid={username},ou=people,dc=wikimedia,dc=org
        """
    )

    bind_user_template = Unicode(
        config=True,
        help="""
        Template from which to construct the full dn
        when authenticating to LDAP. {username} is replaced
        with the actual username.

        Example:

            uid={username},ou=people,dc=wikimedia,dc=org
        """
    )


    allowed_groups = List(
        config=True,
        help="List of LDAP Group DNs whose members are allowed access"
    )

    valid_username_regex = Unicode(
        r'^[a-z][.a-z0-9_\-\@]*[a-z]{2,}$',
        config=True,
        help="""Regex to use to validate usernames before sending to LDAP

        Also acts as a security measure to prevent LDAP injection. If you
        are customizing this, be careful to ensure that attempts to do LDAP
        injection are rejected by your customization
        """
    )

    lookup_dn = Bool(
        False,
        config=True,
        help='Look up the user\'s DN based on an attribute'
    )

    user_search_base = Unicode(
        config=True,
        help="""Base for looking up user accounts in the directory.

        Example:

            ou=people,dc=wikimedia,dc=org
        """
    )

    user_attribute = Unicode(
        config=True,
        help="""LDAP attribute that stores the user's username.

        For most LDAP servers, this is uid.  For Active Directory, it is
        sAMAccountName.
        """
    )

    admin_user = Unicode(
        r'admin',
        config=True,
        help="""Admin password
        """
    )
    admin_password = Unicode(
        r'admin',
        config=True,
        help="""Admin password
        """
    )

    @gen.coroutine
    def authenticate(self, handler, data):
        username = data['username']
        password = data['password']

        # Protect against invalid usernames as well as LDAP injection attacks
        if not re.match(self.valid_username_regex, username):
            self.log.warn('Invalid username')
            return None

        # No empty passwords!
        if password is None or password.strip() == '':
            self.log.warn('Empty password')
            return None

        admindn = self.bind_dn_template.format(username=self.admin_user)

        server = ldap3.Server(
            self.server_address,
            port=self.server_port,
            use_ssl=self.use_ssl
        )

        conn = ldap3.Connection(server, user=admindn, password=self.admin_password)

        if conn.bind():

            conn.search(
                search_base=self.user_search_base,
                search_scope=ldap3.SUBTREE,
                search_filter='({userattr}={username})'.format(
                    userattr=self.user_attribute,
                    username=username
                ),
                attributes=['cn']
            )

            if len(conn.response) == 0:
                self.log.warn('User with {userattr}={username} not found in directory'.format(
                    userattr=self.user_attribute, username=username))
                return None
            #users_dn_attr = conn.response[0]['dn']
            users_dn_attr = conn.response[0]['attributes']['cn'][0]
            print("Got dn_attr:")
            print(users_dn_attr)

            logindn = self.bind_user_template.format(username=users_dn_attr)

            user_conn = ldap3.Connection(server, user=logindn, password=password)

            if user_conn.bind():
                return username
            else:
                self.log.warn('Unable to bind {username}'.format(
                    username=userdn,
                ))
                return None

        else:
            self.log.warn('Invalid password for user {username}'.format(
                username=userdn,
            ))
            return None
