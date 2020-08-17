# coding=UTF-8
"""CAS authentication backend"""
from __future__ import absolute_import, unicode_literals

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ImproperlyConfigured
from sentry_cas_ng.signals import cas_user_authenticated
# from sentry.models import (
#     Organization,
#     OrganizationMember,
#     UserOption,
# )

from .utils import get_cas_client

__all__ = ['CASBackend']


class CASBackend(ModelBackend):
    """CAS authentication backend"""

    def authenticate(self, request, ticket, service):
        """Verifies CAS ticket and gets or creates User object"""
        casCreateUser = getattr(settings, 'CAS_CREATE_USER', True)
        casCreateUserWithID = getattr(settings, 'CAS_CREATE_USER_WITH_ID', false)
        casRenameAttributes = getattr(settings, 'CAS_RENAME_ATTRIBUTES', {})
        casProxyCallback = getattr(settings, 'CAS_PROXY_CALLBACK', None)
        casApplyAttributesToUser = getattr(settings, 'CAS_APPLY_ATTRIBUTES_TO_USER', False)
        authCasDefaultEmailDomain = getattr(settings, 'AUTH_CAS_DEFAULT_EMAIL_DOMAIN', None)
        authCasDefaultSentryOrganization = getattr(settings, 'AUTH_CAS_DEFAULT_SENTRY_ORGANIZATION', False)
        AUTH_CAS_DEFAULT_EMAIL_DOMAIN
        client = get_cas_client(service_url=service, request=request)
        username, attributes, pgtiou = client.verify_ticket(ticket)

        if attributes and request:
            request.session['attributes'] = attributes

        if not username:
            return None
        user = None
        username = self.clean_username(username)

        if attributes:
            reject = self.bad_attributes_reject(request, username, attributes)
            if reject:
                return None

            # If we can, we rename the attributes as described in the settings file
            # Existing attributes will be overwritten
            for cas_attr_name, req_attr_name in casRenameAttributes.items():
                if cas_attr_name in attributes and cas_attr_name is not req_attr_name:
                    attributes[req_attr_name] = attributes[cas_attr_name]
                    attributes.pop(cas_attr_name)

        UserModel = get_user_model()

        # Note that this could be accomplished in one try-except clause, but
        # instead we use get_or_create when creating unknown users since it has
        # built-in safeguards for multiple threads.
        if casCreateUser:
            user_kwargs = {
                UserModel.USERNAME_FIELD: username
            }
            if casCreateUserWithID:
                user_kwargs['id'] = self.get_user_id(attributes)

            user, created = UserModel._default_manager.get_or_create(**user_kwargs)
            if created:
                user = self.configure_user(user)
        else:
            created = False
            try:
                user = UserModel._default_manager.get_by_natural_key(username)
            except UserModel.DoesNotExist:
                pass

        if not self.user_can_authenticate(user):
            return None

        if pgtiou and casProxyCallback and request:
            request.session['pgtiou'] = pgtiou

        if casApplyAttributesToUser and attributes:
            # If we are receiving None for any values which cannot be NULL
            # in the User model, set them to an empty string instead.
            # Possibly it would be desirable to let these throw an error
            # and push the responsibility to the CAS provider or remove
            # them from the dictionary entirely instead. Handling these
            # is a little ambiguous.
            user_model_fields = UserModel._meta.fields
            for field in user_model_fields:
                # Handle null -> '' conversions mentioned above
                if not field.null:
                    try:
                        if attributes[field.name] is None:
                            attributes[field.name] = ''
                    except KeyError:
                        continue
                # Coerce boolean strings into true booleans
                if field.get_internal_type() == 'BooleanField':
                    try:
                        boolean_value = attributes[field.name] == 'True'
                        attributes[field.name] = boolean_value
                    except KeyError:
                        continue

            user.__dict__.update(attributes)
            # 添加 sentry 属性
            # email
            try:
                from sentry.models import (UserEmail)
            except ImportError:
                pass
            elif:
                if user.email is not None:
                    email = user.email
                elif not hasattr(settings, 'AUTH_CAS_DEFAULT_EMAIL_DOMAIN'):
                    email = ''
                elif authCasDefaultEmailDomain is not None:
                    email = username + '@' + authCasDefaultEmailDomain

                # django-auth-ldap may have accidentally created an empty email address
                UserEmail.objects.filter(Q(email='') | Q(email=' '), user=user).delete()
                if email:
                    UserEmail.objects.get_or_create(user=user, email=email)
            # 组织与角色权限
            if authCasDefaultSentryOrganization:
                orgs = OrganizationMember.objects.filter(user=user)
                if orgs is None or len(orgs) == 0:
                    organizations = Organization.objects.filter(name=authCasDefaultSentryOrganization)
                    member_role = getattr(settings, 'AUTH_CAS_SENTRY_ORGANIZATION_ROLE_TYPE', None)
                    has_global_access = getattr(settings, 'AUTH_CAS_SENTRY_ORGANIZATION_GLOBAL_ACCESS', False)
                    OrganizationMember.objects.create(
                        organization=organizations[0],
                        user=user,
                        role=member_role,
                        has_global_access=has_global_access,
                        flags=getattr(OrganizationMember.flags, 'sso:linked'),
                    )
            # If we are keeping a local copy of the user model we
            # should save these attributes which have a corresponding
            # instance in the DB.
            if casCreateUser:
                user.save()

        # send the `cas_user_authenticated` signal
        cas_user_authenticated.send(
            sender=self,
            user=user,
            created=created,
            attributes=attributes,
            ticket=ticket,
            service=service,
            request=request
        )
        return user

    # ModelBackend has a `user_can_authenticate` method starting from Django
    # 1.10, that only allows active user to log in. For consistency,
    # django-cas-ng will have the same behavior as Django's ModelBackend.
    if not hasattr(ModelBackend, 'user_can_authenticate'):
        def user_can_authenticate(self, user):
            return True

    def get_user_id(self, attributes):
        """
        For use when CAS_CREATE_USER_WITH_ID is True. Will raise ImproperlyConfigured
        exceptions when a user_id cannot be accessed. This is important because we
        shouldn't create Users with automatically assigned ids if we are trying to
        keep User primary key's in sync.
        """
        if not attributes:
            raise ImproperlyConfigured("CAS_CREATE_USER_WITH_ID is True, but "
                                       "no attributes were provided")

        user_id = attributes.get('id')

        if not user_id:
            raise ImproperlyConfigured("CAS_CREATE_USER_WITH_ID is True, but "
                                       "`'id'` is not part of attributes.")

        return user_id

    def clean_username(self, username):
        """
        Performs any cleaning on the "username" prior to using it to get or
        create the user object.  Returns the cleaned username.

        By default, changes the username case according to
        `settings.CAS_FORCE_CHANGE_casForceChangeUsernameCase`.
        """
        casForceChangeUsernameCase = getattr(settings, 'CAS_FORCE_CHANGE_USERNAME_CASE', None)
        if casForceChangeUsernameCase == 'lower':
            username = username.lower()
        elif casForceChangeUsernameCase == 'upper':
            username = username.upper()
        elif casForceChangeUsernameCase is not None:
            raise ImproperlyConfigured(
                "Invalid value for the CAS_FORCE_CHANGE_casForceChangeUsernameCase setting. "
                "Valid values are `'lower'`, `'upper'`, and `None`.")
        return username

    def configure_user(self, user):
        """
        Configures a user after creation and returns the updated user.

        By default, returns the user unmodified.
        """
        return user

    def bad_attributes_reject(self, request, username, attributes):
        return False
