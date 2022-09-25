import datetime
from collections import defaultdict

from operator import itemgetter

from itertools import groupby

import logging

import json
from tokenize import Number
from venv import create
from django.conf import settings

from django.db.transaction import atomic
from django.utils.timezone import localtime


from api import models
from api.models import KeyValueStore,LineBotUser
from lib import misc
from lib.exceptions import ErrorMessageForUser, NotRegisteredException
from lib.line import LineBotApiWrapper, LineApp, LiffHelper


_CHANNEL_MODEL_MAP = {
    'client': LineBotUser,
}

logger = logging.getLogger(__name__)


class UnregisteredFakeUser:
    def __init__(self, line_uid=None, phone_number=None, channel_type=None):
        self.line_uid = line_uid
        self.phone_number = phone_number
        self.channel_type = channel_type

    def __str__(self):
        return '(未註冊的使用者: {})'.format(self.phone_number or self.line_uid)

    def save(self):
        pass


def load_frontend_constants():
    path = settings.ROOT_DIR_PATH.joinpath('static_src/constants.json')
    with open(path) as f:
        return json.load(f)


class BaseBotUserInitiator:
    def init_bot_user(self, *, line_uid='', phone_number='', channel_type=None,
                      create=False, fake=False):
        from lib.line import LineBotApiWrapper
        assert line_uid or phone_number
        assert channel_type
        line_uid = line_uid or ''
        phone_number = phone_number or ''

        model_class = channel_type_to_model(channel_type)

        def _first(queryset):
            return queryset.order_by('id').first()

        bot_user = None
        if line_uid:
            bot_user = _first(model_class.objects.filter(line_uid=line_uid))

        if not bot_user and phone_number:
            bot_user = _first(
                model_class.objects.filter(phone_number=phone_number))

        if not bot_user:
            kwargs = {'phone_number': phone_number, 'line_uid': line_uid}
            bot_user = _first(model_class.objects.filter(**kwargs))

            if not bot_user and create:
                bot_user = model_class.objects.create(**kwargs)
                

        if not bot_user:
            if fake:
                return UnregisteredFakeUser(
                    line_uid=line_uid, phone_number=phone_number,
                    channel_type=channel_type)
            raise NotRegisteredException()

        following = KeyValueStore.pop('line_following_{}'.format(line_uid))
        bot_user.following = True
        bot_user.save()

        if line_uid and not bot_user.line_uid:
            bot_user.line_uid = line_uid
            bot_user.save()

        if not bot_user.name and line_uid:
            try:
                profile = LineBotApiWrapper(
                    channel_type=channel_type).get_profile(
                    line_uid)
                bot_user.name = profile.display_name
                bot_user.picture_url = profile.picture_url
                bot_user.save()
            except:
                pass

        return bot_user


class ClientBotUserInitiator(BaseBotUserInitiator):
    def init_bot_user(self, **kwargs):
        bot_user = super().init_bot_user(**kwargs)
        return bot_user


class StoreBotUserInitiator(BaseBotUserInitiator):
    pass


def init_bot_user(*, line_uid='', phone_number='', channel_type=None,
                  create=False, fake=False):
    initiator = {
        'client': ClientBotUserInitiator,
        'store': StoreBotUserInitiator,
    }[channel_type]()
    return initiator.init_bot_user(
        line_uid=line_uid, phone_number=phone_number,
        channel_type=channel_type,
        create=create, fake=fake)


def channel_type_to_model(channel_type):
    return _CHANNEL_MODEL_MAP[channel_type]


def get_or_init_user_from_request(request, channel_type, phone_number=None,
                                  create=False):
    from lib import auth
    uid = auth.get_line_user_id(request)
    bot_user = init_bot_user(
        line_uid=uid, channel_type=channel_type, phone_number=phone_number,
        create=create)
    return bot_user



def censor_phone(phone_number):
    return '{}{}{}'.format(
        phone_number[:4],
        '*' * 3,
        phone_number[-3:],
    )


def check_registered(bot_user):
    # return False
    return bot_user.phone_number


def on_registration_complete(bot_user):
    profile = bot_user


def get_line_OA_url():
    id = settings.LINE_OA_ID
    if not id:
        return ''

    return 'https://line.me/ti/p/{}'.format(id)



def get_liff_url(liff_name, channel_type='client'):
    login_api = LineApp(channel_type).login_api
    return LiffHelper(login_api).get_url_by_liff_name(liff_name)

