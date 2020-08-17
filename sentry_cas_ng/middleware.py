# coding=UTF-8
"""CAS authentication middleware"""

from __future__ import absolute_import, unicode_literals

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from django.utils.six.moves import urllib_parse
from django.utils.translation import ugettext_lazy as _

from .utils import (
    get_cas_client,
    get_protocol,
    get_redirect_url,
    get_service_url,
    get_user_from_session,
)
from .signals import cas_user_logout
from .models import ProxyGrantingTicket, SessionTicket
import re
import logging
logging.basicConfig()
logger = logging.getLogger('sentry-cas')
__all__ = ['CASMiddleware']


class CASMiddleware(MiddlewareMixin):
    """Middleware that allows CAS authentication on admin pages"""
    def cas_successful_login(self):
        return HttpResponseRedirect('/admin/')

    def process_request(self, request):
        # 已经登录则放过
        # cas 时进入 cas 登录逻辑
        casLoginReg = getattr(settings, 'CAS_LOGIN_REG', None)
        casLogoutReg = getattr(settings, 'CAS_LOGOUT_REG', None)
        casProxyCallback = getattr(settings, 'CAS_PROXY_CALLBACK', None)
        logger.warn('1--------------------------------')
        logger.warn(request.path)
        logger.warn(casLoginReg)
        logger.warn('1--------------------------------')
        if casLoginReg is not None and re.match(casLoginReg, request.path):
            logger.warn('2--------------------------------')
            logger.warn(request.user)
            logger.warn(request.user.is_authenticated)
            logger.warn('2--------------------------------')
            if request.user.is_authenticated:
                logger.warn(request.user.is_authenticated)
                return self.cas_successful_login()
            service_url = get_service_url(request, request.GET.get('next'))
            client = get_cas_client(service_url=service_url, request=request)
            ticket = request.GET.get('ticket')
            shortTicket = ''
            if ticket:
                shortTicket = ticket[0:30]
            logger.warn('ticket')
            # ticket 验证阶段
            if ticket:
                pgtiou = request.session.get("pgtiou")
                logger.warn(ticket)
                
                user = authenticate(ticket=ticket,
                                shortTicket=shortTicket,
                                service=service_url,
                                request=request)
                logger.warn(user.get_username())
                # 如果登录成功
                if user is not None:
                    if not request.session.exists(request.session.session_key):
                        request.session.create()
                    auth_login(request, user)
                    logger.warn('0----------------login success')
                    logger.warn(request.session.session_key)
                    logger.warn(ticket)
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
                    return HttpResponseRedirect('/')
                else:
                    return HttpResponseRedirect(client.get_login_url())
            else:
                return HttpResponseRedirect(client.get_login_url())
        elif casLogoutReg is not None and re.match(casLogoutReg, request.path):
            try:
                st = SessionTicket.objects.get(session_key=request.session.session_key)
                ticket = st.ticket
            except SessionTicket.DoesNotExist:
                ticket = None
            # send logout signal
            cas_user_logout.send(
                sender="manual",
                user=request.user,
                session=request.session,
                ticket=shortTicket,
            )
            auth_logout(request)
            # clean current session ProxyGrantingTicket and SessionTicket
            ProxyGrantingTicket.objects.filter(session_key=request.session.session_key).delete()
            SessionTicket.objects.filter(session_key=request.session.session_key).delete()
            pass
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
