from django.conf import settings
from django.db.models import Q
from linebot import LineBotApi
from linebot.http_client import RequestsHttpResponse
from linebot.exceptions import LineBotApiError
from linebot.models import (RichMenu, SendMessage, TextSendMessage)
from cachetools.func import ttl_cache
import logging
import requests
from lib import misc
from urllib.parse import urljoin
from api.models import QueuedLineMessage,ChatMessage,LineBotUser,LiffAppSetting,RichMenuSetting
import re
import json
from mimetypes import guess_type
import os


_SECRET_MAPPING = {
    'client': {
        'login': {
            'id': settings.LOGIN_CHANNEL_ID,
            'secret': settings.LOGIN_CHANNEL_SECRET,
        },
        'message': {
            'secret': settings.CHANNEL_SECRET,
            'access_token': settings.CHANNEL_ACCESS_TOKEN,
        },
    }
}
LINE_API_MESSAGE_NUM_LIMIT = 5  # LINE API 一次可以傳幾個 message
LINE_API_MESSAGE_LENGTH_LIMIT = 2000  # LINE 的 純文字訊息最多可以有幾個字
LINE_API_TEMPLATE_TEXT_LIMIT = 160  # LINE 的 template 最多可以有幾個字
LIFF_API_PATH = '/liff/v1/apps'  # https://developers.line.biz/en/news/2022/03/09/liff-server-api/

API_HOST = 'https://api.line.me'
API_ISSUE_ACCESS_TOKEN = '/v2/oauth/accessToken'
TOKEN_CACHE_TTL = 24 * 60 * 60  # Login channel short-lived token cache 的 TTL

logger = logging.getLogger(__name__)

TOKEN_FOR_DEVELOPMENT = 'fake_access_token_55667788'
ID_FOR_DEV = 'fake_id_123'

class LineApp:
    def __init__(self, type):
        self.type = type

        mapping = _SECRET_MAPPING[type]

        self.api = LineBotApiWrapper(type)
        self.login_api = LoginChannelApi(type, mapping['login']['id'],
                                         mapping['login']['secret'])


class BaseLineChannel:
    secret = None
    access_token = None
    type = None

    def __init__(self, secret, access_token):
        self.secret = secret
        self.access_token = access_token

    @classmethod
    def create(cls, channel_type):
        klass = {
            'client': ClientLineChannel,
        }[channel_type]
        return klass()                                

class LineBotApiWrapper(LineBotApi):
    CHANNEL_CLASS = BaseLineChannel

    def __init__(self, channel_type, app=None, reply_token=None,
                 wrapper_dict=None, access_token=None):
        self.channel = app or self.CHANNEL_CLASS.create(channel_type)
        self.channel_type = channel_type

        super().__init__(access_token or self.channel.access_token)
        wrapper_dict = wrapper_dict or {}
        self.reply_token = reply_token or wrapper_dict.get('reply_token')

    def is_dry_run(self):
        return False
        return settings.LINE_DRY_RUN

    def _post(self, path, data=None, headers=None, timeout=None,
              endpoint=None):
        if self.is_dry_run():
            return

        try:
            return super()._post(path, endpoint=endpoint, data=data,
                                 headers=headers, timeout=timeout)
        except:
            logger.debug('_post {} {}'.format(path, data))
            raise

    def _put(self, path, data=None, headers=None, timeout=None):
        if self.is_dry_run():
            return

        url = self.endpoint + path

        if headers is None:
            headers = {}
        headers.update(self.headers)

        try:
            response = RequestsHttpResponse(requests.put(
                url, headers=headers, json=data, timeout=timeout
            ))
        except:
            logger.debug('_put {} {}'.format(path, data))
            raise

        # name mangling https://aji.tw/python你到底是在__底線__什麼啦/
        self._LineBotApi__check_error(response)
        return response

    def reply_message(self, reply_token, messages, notification_disabled=False,
                      timeout=None, bot_user=None, dry_run=False,
                      add_slack_tags=False):
        message_objs = self._to_message_objects(messages)
        if not dry_run:
            super().reply_message(reply_token, message_objs,
                                  notification_disabled, timeout)
        self._notify_message_sent(bot_user, message_objs, dry_run=dry_run)

    def push_message(self, to, messages, notification_disabled=False,
                     timeout=None, dry_run=False, add_slack_tags=False):

        message_objs = self._to_message_objects(messages)

        error = None
        try:
            for batch in misc.grouper(LINE_API_MESSAGE_NUM_LIMIT,
                                      message_objs):
                if not dry_run:
                    super().push_message(to, batch, notification_disabled,
                                         timeout)
        except LineBotApiError as e:
            error = e
            misc.report_exception()

        self._notify_message_sent(to, message_objs, error=error,
                                  dry_run=dry_run,
                                  add_slack_tags=add_slack_tags)

    def _call_async(self, method, *args, countdown=0, **kwargs):
        eta = misc.count_celery_eta(countdown)
        kwargs2 = {
            **{
                'wrapper_kwargs': {
                    'channel_type': self.channel.type,
                }, }, **kwargs
        }
        method.apply_async(args, kwargs2, eta=eta)

    def reply_message_async(self, *args, **kwargs):
        from api import tasks

        self._call_async(tasks.reply_message, *args, **kwargs)

    def push_message_async(self, *args, **kwargs):
        from api import tasks
        self._call_async(tasks.push_message, *args, **kwargs)

    def send_message_async(self, *args, **kwargs):
        from api import tasks
        self._call_async(tasks.send_message, *args, **kwargs)
        # 雖然要等非同步執行 但還是可以先取消 reply token
        self.reply_token = None

    def _get_wrapper_dict(self):
        return {
            'reply_token': self.reply_token
        }

    def send_message(self, to, *args, retry_count=0, **kwargs):

        bot_user = self.get_bot_user(to)
        line_uid = bot_user.line_uid
        if bot_user and (not bot_user.following or not line_uid):
            messages = args[0]
            QueuedLineMessage.objects.create(
                bot_user=bot_user,
                content=messages,
                extra_info={
                    'kwargs': kwargs,
                }
            )
            logger.debug(
                '{} 未追蹤本頻道，加到待發訊息中：{}'.format(
                    bot_user, messages))
            return

        if self.reply_token:
            self.reply_message(self.reply_token, *args, bot_user=to, **kwargs)
            self.reply_token = None
            return

        assert re.search(r'^U[a-f\d]+', line_uid), '使用者ID格式不正確：{}'.format(
            line_uid)
        self.push_message(line_uid, *args, **kwargs)

    def _to_message_objects(self, messages):
        if not isinstance(messages, (list, tuple)):
            messages = [messages]

        messages = [TextSendMessage(text=m)
                    if isinstance(m, str) else
                    RawSendMessage(m) if isinstance(m, dict) else
                    m for m in messages]

        for m in messages:
            if isinstance(m, TextSendMessage):
                m.text = misc.text_with_length_limit(
                    m.text, LINE_API_MESSAGE_LENGTH_LIMIT)
            elif getattr(m, 'type') == 'template':
                m.template['text'] = misc.text_with_length_limit(
                    m.template['text'], LINE_API_TEMPLATE_TEXT_LIMIT)

        return messages

    def _notify_message_sent(self, bot_user, messages, error=None,
                             dry_run=False, add_slack_tags=False):
        messages = self._to_message_objects(messages)
        bot_user = self.get_bot_user(bot_user)
        ChatMessage.objects.create(
            bot_user=bot_user,
            message=json.loads(str(messages)),
            to_user=True,
        )

        msg = '{} > to  *{}* : {}'.format(
            '(測試用，並沒有真的送出)' if dry_run or self.is_dry_run() else '', bot_user,
            '\n'.join([getattr(m, 'text', str(m)) for m in messages]).strip())

        if error:
            msg += ' 傳送 line 訊息時發生錯誤：{}'.format(error.message)

        print(msg)

    def get_menu_helper(self):
        return RichMenuHelper(self)

    def sync_liff_apps(self):
        return LiffHelper(self).sync_liff_apps()

    def get_bot_user(self, bot_user_or_line_uid):
        if isinstance(bot_user_or_line_uid, LineBotUser):
            return bot_user_or_line_uid

        model = {
            'client': LineBotUser,
        }[self.channel_type]
        try:
            return model.objects.get(line_uid=bot_user_or_line_uid)
        except model.DoesNotExist:
            return None

@ttl_cache(ttl=TOKEN_CACHE_TTL)
def issue_short_lived_token(id, secret):
    assert id
    assert secret
    res = requests.post('%s%s' % (API_HOST, API_ISSUE_ACCESS_TOKEN), data={
        'grant_type': 'client_credentials',
        'client_id': id,
        'client_secret': secret,
    })
    data = res.json()
    logger.debug('issue_short_lived_token: {}'.format(data))

    return data['access_token']


class RichMenuHelper:
    def __init__(self, line_bot_api_wrapper):
        self.api_wrapper = line_bot_api_wrapper
        self.menu_cache = {}
        self.channel_type = line_bot_api_wrapper.channel_type

    def upload_rich_menu_image(self, file_path, menu_id):
        with open(file_path, 'rb') as f:
            content_type = guess_type(file_path)[0]
            self.api_wrapper.set_rich_menu_image(menu_id, content_type, f)

    def _create_rich_menu_obj(self, rich_menu_or_dict, timeout=None):
        if isinstance(rich_menu_or_dict, RichMenu):
            config_dict = rich_menu_or_dict.as_json_string()
        else:
            config_dict = rich_menu_or_dict

        response = self.api_wrapper._post(
            '/v2/bot/richmenu', data=json.dumps(config_dict),
            timeout=timeout
        )

        return response.json.get('richMenuId')

    def upload_rich_menu(self, menu_config, image_path):
        menu_id = self._create_rich_menu_obj(menu_config)
        self.upload_rich_menu_image(image_path, menu_id)
        return menu_id

    def upload_rich_menu_by_name(self, menu_name):
        image_path, menu_config = self.get_menu_image_path_and_config(
            menu_name)

        return self.upload_rich_menu(menu_config, image_path)

    def get_menu_image_path_and_config(self, menu_name):
        menu_dir = os.path.join(settings.BASE_DIR, 'menus')
        image_path = os.path.join(menu_dir, '{}.png'.format(
            menu_name))
        config_path = os.path.join(menu_dir, '{}.json'.format(
            menu_name))

        with open(config_path) as f:
            config = json.load(f)
            for a in config['areas']:
                action = a['action']
                liff_name = action.pop('liff_name', None)
                if liff_name:
                    action['uri'] = LiffHelper(
                        self.api_wrapper).get_url_by_liff_name(liff_name)

        return image_path, config

    def check_menu_changed(self, menu_id, menu_name):
        if not menu_id:
            return True

        menu = RichMenuSetting.objects.filter(menu_id=menu_id).last()
        if not menu or not menu.content_hash:
            return True

        content_hash = self.compute_menu_content_hash(menu_name)
        if menu.content_hash != content_hash:
            return True

        return False

    def sync_menu(self, menu_name):
        menu = self.get_menu(menu_name)

        old_menu_id = menu.menu_id if menu else None
        logger.debug('Existing menu_id for {}: {}'.format(
            menu_name, old_menu_id))

        menu_changed = self.check_menu_changed(old_menu_id, menu_name)

        if not menu_changed:
            logger.debug('Menu not changed.')
            return old_menu_id

        new_menu_id = self.upload_rich_menu_by_name(menu_name)
        logger.debug('New menu_id for {}: {}'.format(
            menu_name, new_menu_id))

        if old_menu_id:
            try:
                self.api_wrapper.delete_rich_menu(old_menu_id)
            except LineBotApiError as e:
                if e.status_code != 404:
                    raise

        if not menu:
            menu = RichMenuSetting.objects.create(name=menu_name)

        content_hash = self.compute_menu_content_hash(menu_name)
        menu.menu_id = new_menu_id
        menu.content_hash = content_hash
        menu.save()

        return new_menu_id

    def get_menu(self, menu_name):
        try:
            menu = RichMenuSetting.objects.get(name=menu_name)
        except RichMenuSetting.DoesNotExist:
            menu = None
        return menu

    def update_default_rich_menu(self):
        menu_name = 'pycg_menu'

        old_menu = self.get_menu(menu_name)
        old_menu_id = old_menu.menu_id if old_menu else None

        new_menu_id = self.sync_menu(menu_name)
        if new_menu_id == old_menu_id:
            logger.debug('Default menu unchanged.')
        else:
            self.api_wrapper.set_default_rich_menu(new_menu_id)

            default_menu = RichMenuSetting.objects.get(name=menu_name)
            model = {
                'client': LineBotUser,
            }[self.api_wrapper.channel_type]
            users = model.objects.filter(
                Q(active_menu=default_menu) | Q(active_menu__isnull=True)
            ).exclude(uid=ID_FOR_DEV)
            if users:
                user_uids = [u.line_uid for u in users if u.line_uid]
                self.api_wrapper.unlink_rich_menu_from_users(user_uids)
                users.update(active_menu=default_menu)

            logger.debug('Default menu updated.')

    def link_menu(self, menu_name, user_id):
        import lib.business_misc
        menu_id = self.sync_menu(menu_name)

        user = lib.business_misc.init_bot_user(line_uid=user_id,
                                               channel_type=self.channel_type)
        self.api_wrapper.link_rich_menu_to_user(user_id, menu_id)
        user.active_menu = RichMenuSetting.objects.get(name=menu_name)
        user.save()

    def compute_menu_content_hash(self, menu_name):
        image_path, config = self.get_menu_image_path_and_config(
            menu_name)

        config_hash = misc.md5(config)
        image_hash = misc.md5(image_path)
        return image_hash + config_hash


class LiffHelper:
    def __init__(self, api_wrapper):
        self.api_wrapper = api_wrapper
        self.channel_type = api_wrapper.channel_type

    def get_liff_config(self):
        raw = misc.load_config(
            'liff_apps_{}.yml'.format(self.channel_type))

        return [{
            'description': app['description'],
            'view': {
                'type': app['type'],
                'url': urljoin(settings.DEFAULT_HOST_URL, app['path']),
            },
        } for app in raw]

    def get_url_by_liff_name(self, liff_name, protocol='https'):
        liff_id = LiffAppSetting.objects.get(
            name=liff_name, channel_type=self.channel_type).liff_id
        template = {
            'https': 'https://liff.line.me/{}',
            'line': 'line://app/{}',
        }
        return template[protocol].format(liff_id)

    def get_liff_apps_by_api(self):
        try:
            return self.api_wrapper._get(LIFF_API_PATH).json['apps']
        except LineBotApiError as e:
            if e.status_code != 404:
                raise
            else:
                return []

    def sync_liff_apps(self):
        config = self.get_liff_config()
        liff_names = [app['description'] for app in config]
        liff_info_map = self.get_liff_info_map_from_db_or_api(liff_names)

        for app in config:
            liff_name = app['description']
            liff_info = liff_info_map.get(liff_name)
            new_hash = self.get_liff_hash(app)
            # app['bot_prompt'] = 'aggressive'

            if not liff_info:
                print("dsfasfasd")
                print(app)
                self.create_liff(app)
                logger.debug('New LIFF created : -> {}'.format(app))
                continue

            liff_id = liff_info['liff_id']

            if liff_info['hash'] != new_hash:
                logger.debug('Update liff : -> {}'.format(app))
                self.update_liff(liff_id, app)
            else:
                logger.debug('No need to update liff {}'.format(liff_id))
                liff, created = LiffAppSetting.objects.get_or_create(
                    channel_type=self.channel_type,
                    name=liff_name, defaults={
                        'name': liff_name,
                        'liff_id': liff_id,
                        'content_hash': new_hash,
                    })
                if created:
                    logger.debug(
                        'New LiffAppSetting object created: {}'.format(liff))

    def get_liff_info_map_from_db_or_api(self, desired_liff_names):
        liffs = LiffAppSetting.objects.filter(channel_type=self.channel_type)
        if set([l.name for l in liffs]).issubset(set(desired_liff_names)):
            return {
                l.name: {
                    'hash': l.content_hash,
                    'liff_id': l.liff_id,
                } for l in liffs
            }

        map_ = {}
        uploaded_liffs = self.get_liff_apps_by_api()
        for l in uploaded_liffs:
            map_[l['description']] = {
                'hash': self.get_liff_hash(l),
                'liff_id': l['liffId'],
            }

        return map_

    def get_liff_hash(self, l):
        without_id = l.copy()
        without_id.pop('liffId', None)
        return misc.md5(without_id)

    def update_liff(self, liff_id, app):
        assert liff_id
        self.api_wrapper._put('{}/{}'.format(LIFF_API_PATH, liff_id), app)
        self.created_liff_setting(app, liff_id)

    def create_liff(self, app):
        res = self.api_wrapper._post(LIFF_API_PATH, json.dumps(app))
        print(res)
        liff_id = res.json['liffId']
        self.created_liff_setting(app, liff_id)

    def created_liff_setting(self, app, liff_id):
        liff_name = app['description']
        liff, _ = LiffAppSetting.objects.get_or_create(
            channel_type=self.channel_type, name=liff_name)
        liff.content_hash = self.get_liff_hash(app)
        liff.liff_id = liff_id
        liff.save()


class SocialApi:
    def __init__(self, user_access_token):
        self.access_token = user_access_token

    def verify_user_access_token(self):
        res = requests.get('https://api.line.me/oauth2/v2.1/verify', {
            'access_token': self.access_token
        })
        res.raise_for_status()
        return res.json()

    def get_profile(self):
        if TOKEN_FOR_DEVELOPMENT and self.access_token == TOKEN_FOR_DEVELOPMENT:
            return {'userId': ID_FOR_DEV}

        res = requests.get('https://api.line.me/v2/profile', headers={
            'Authorization': 'Bearer {}'.format(self.access_token)
        })
        result = res.json()
        logger.debug('get_profile: {}'.format(result))
        res.raise_for_status()
        return result

    def get_user_id(self):
        return self.get_profile()['userId']


class LoginChannelApi(LineBotApiWrapper):
    CHANNEL_CLASS = BaseLineChannel

    def __init__(self, channel_type, id, secret):
        self.channel_type = channel_type
        self.id = id
        self.secret = secret
        self.access_token = issue_short_lived_token(id, secret)

        super().__init__(channel_type, access_token=self.access_token)

class ClientLineChannel(BaseLineChannel):
    type = 'client'

    def __init__(self):
        super().__init__(settings.CHANNEL_SECRET,
                         settings.CHANNEL_ACCESS_TOKEN)

class RawSendMessage(SendMessage):
    def __init__(self, dict_, **kwargs):
        super().__init__(**kwargs)
        self.__dict__.update(**dict_)

    def __str__(self):
        return json.dumps(self.__dict__, ensure_ascii=False)
