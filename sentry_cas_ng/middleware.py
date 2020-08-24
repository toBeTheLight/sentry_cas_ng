# coding=UTF-8
"""CAS authentication middleware"""

from __future__ import absolute_import, unicode_literals

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.signals import user_logged_out
from django.dispatch import receiver
from sentry_cas_ng.signals import cas_user_logout
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from django.utils.six.moves import urllib_parse
from django.utils.translation import ugettext_lazy as _

from .utils import (
    get_cas_client,
    get_protocol,
    get_service_url,
    get_user_from_session,
)
from .models import ProxyGrantingTicket, SessionTicket
import re
import logging
logging.basicConfig()
logger = logging.getLogger('sentry-cas')
__all__ = ['CASMiddleware']

class CASMiddleware(MiddlewareMixin):
    """Middleware that allows CAS authentication on admin pages"""
    def cas_successful_login(self, user, request):
        if user.session_nonce is not None:
            request.session["_nonce"] = user.session_nonce
        casLoginSuccessPath = getattr(settings, 'CAS_LOGIN_SUCCESS_PATH', '/')
        return HttpResponseRedirect(casLoginSuccessPath)

    def cas_success_logout(self, request):
        logger.debug('----------logout----------')
        sts = SessionTicket.objects.filter(session_key=request.session.session_key)
        if len(sts) == 0:
            return
        try:
            st = sts[0]
            ticket = st.ticket[0:30]
        except SessionTicket.DoesNotExist:
            ticket = None
        logger.debug(ticket)
        # send logout signal
        cas_user_logout.send(
            sender="manual",
            user=request.user,
            session=request.session,
            ticket=ticket,
        )
        # clean current session ProxyGrantingTicket and SessionTicket
        ProxyGrantingTicket.objects.filter(session_key=request.session.session_key).delete()
        SessionTicket.objects.filter(session_key=request.session.session_key).delete()

    def process_request(self, request):
        # 已经登录则放过
        # cas 时进入 cas 登录逻辑
        casLoginRequestJudge = getattr(settings, 'CAS_LOGIN_REQUEST_JUDGE', None)
        casLogoutRequestJudge = getattr(settings, 'CAS_LOGOUT_REQUEST_JUDGE', None)
        casProxyCallback = getattr(settings, 'CAS_PROXY_CALLBACK', None)
        casLoginReturn = getattr(settings, 'CAS_LOGIN_RETURN', None)
        logger.debug('=============' + request.path + '===============')
        if casLoginRequestJudge is not None and casLoginRequestJudge(request):
            logger.debug('=============login logic===============')
            protocol = get_protocol(request)
            host = request.get_host()
            casLoginReturnUrl = urllib_parse.urlunparse(
                (protocol, host, request.path, '', '', ''),
            )
            logger.debug('============= casLoginReturnUrl ===============')
            if request.user.is_authenticated:
                logger.debug('=============logined===============')
                return self.cas_successful_login(user=request.user, request=request)
            service_url = get_service_url(request, request.GET.get('next'))
            client = get_cas_client(service_url=casLoginReturnUrl, request=request)
            ticket = request.GET.get('ticket')
            shortTicket = ''
            if ticket:
                logger.debug('=============ticket logic===============')
                shortTicket = ticket[0:30]
                pgtiou = request.session.get("pgtiou")
                logger.debug(ticket)
                
                user = authenticate(ticket=ticket,
                                shortTicket=shortTicket,
                                service=service_url,
                                request=request)
                # 如果登录成功
                if user is not None:
                    logger.debug('=============ticket logic===============')
                    # If this User has a nonce value, we need to bind into the session.
                    if not request.session.exists(request.session.session_key):
                        request.session.create()
                    auth_login(request, user)
                    logger.debug('=============login success===============')
                    logger.debug(request.session.session_key)
                    SessionTicket.objects.create(
                        session_key=request.session.session_key,
                        ticket=shortTicket
                    )

                    if pgtiou and casProxyCallback:
                        # Delete old PGT
                        ProxyGrantingTicket.objects.filter(
                            user=user,
                            session_key=request.session.session_key
                        ).delete()
                        # Set new PGT ticket
                        try:
                            pgt = ProxyGrantingTicket.objects.get(pgtiou=pgtiou)
                            pgt.user = user
                            pgt.session_key = request.session.session_key
                            pgt.save()
                        except ProxyGrantingTicket.DoesNotExist:
                            pass
                    logger.debug('=============redirect login success===============')
                    return self.cas_successful_login(user=user, request=request)
                else:
                    logger.debug('=============redirect login===============')
                    return HttpResponseRedirect(client.get_login_url())
            # elif len(SessionTicket.objects.filter(session_key=request.session.session_key)) == 0:
            #     # 如果没有 ticket 那么曾主动退出登录或登录已经过期，跳转至 sso 重新登录
            #     logger.debug('=============redirect logout===============')
            #     return HttpResponseRedirect(client.get_login_url())
            else:
                logger.debug('=============redirect login unknow===============')
                return HttpResponseRedirect(client.get_login_url())
        elif casLogoutRequestJudge is not None and casLogoutRequestJudge(request):
            self.cas_success_logout(request=request)
            pass
            # try:
            #     st = SessionTicket.objects.get(session_key=request.session.session_key)
            #     ticket = st.ticket
            # except SessionTicket.DoesNotExist:
            #     ticket = None
            # # send logout signal
            # cas_user_logout.send(
            #     sender="manual",
            #     user=request.user,
            #     session=request.session,
            #     ticket=shortTicket,
            # )
            # auth_logout(request)
            # # clean current session ProxyGrantingTicket and SessionTicket
            # ProxyGrantingTicket.objects.filter(session_key=request.session.session_key).delete()
            # SessionTicket.objects.filter(session_key=request.session.session_key).delete()
            # pass
        else:
            pass
        """Checks that the authentication middleware is installed"""

        error = ("The Django CAS middleware requires authentication "
                 "middleware to be installed. Edit your MIDDLEWARE_CLASSES "
                 "setting to insert 'django.contrib.auth.middleware."
                 "AuthenticationMiddleware'.")
        assert hasattr(request, 'user'), error

    def process_view(self, request, view_func, view_args, view_kwargs):
        pass
