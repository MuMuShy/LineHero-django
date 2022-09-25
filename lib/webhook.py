import logging
import json
from venv import create
from linebot import LineBotApi
from linebot.models import (
    MessageEvent, TextMessage, TextSendMessage,FlexSendMessage,
    RichMenuArea, RichMenuBounds, URIAction, RichMenuSize, RichMenu,
    SendMessage, FollowEvent, UnfollowEvent, Message, AudioMessage,
    VideoMessage, ImageMessage)
from django.conf import settings
from lib import business_misc,line
from lib.business_misc import UnregisteredFakeUser
from api.models import ChatMessage, LineEvent, KeyValueStore,Player
import abc
logger = logging.getLogger(__name__)

class BaseEventHandler(metaclass=abc.ABCMeta):

    def __init__(self, request):
        #self.api_wrapper = LineBotApiWrapper(self.line_channel_type)
        self.line_api = LineBotApi(settings.CHANNEL_ACCESS_TOKEN)
        self.request = request
    
    @classmethod
    def create(cls, channel_type, *args, **kwargs):
        return {
            'client': ClientEventHandler,
        }[channel_type](*args, **kwargs)


    def handle_event(self, event):
        logger.debug('event: {}'.format(json.loads(str(event))))
        line_uid = event.source.user_id

        bot_user = self.init_bot_user(line_uid)
        if (isinstance(bot_user,UnregisteredFakeUser)):
            bot_user = self.get_bot_user(line_uid)

        registered = not self.is_not_registered(bot_user)

        self.notify_event(bot_user, event)

        self.log_event(bot_user, event)

        if isinstance(event, FollowEvent):
            self.line_api.reply_message(event.reply_token,TextSendMessage("歡迎 冒險者"))
            if Player.objects.filter(line_user = bot_user).exists() is False:
                player = Player.objects.create(line_user = bot_user,nick_name = bot_user.name)
                player.save()
            bot_user.following = True
            bot_user.save()
            KeyValueStore.set('line_following_{}'.format(line_uid),
                                True)

            return

        if not isinstance(event, MessageEvent):
            return

        if not isinstance(event.message, TextMessage):
            return


        self.line_api.reply_message(event.reply_token,TextSendMessage("test"))
    
    @abc.abstractmethod
    def init_bot_user(self, line_uid):
        raise NotImplemented
    @abc.abstractmethod
    def get_bot_user(self, line_uid):
        raise NotImplemented
    
    def notify_event(self, bot_user, event):
        if isinstance(event, FollowEvent):
            msg = '(開始追蹤／解除封鎖)'
        elif isinstance(event, UnfollowEvent):
            msg = '(已封鎖此頻道)'
        elif not isinstance(event, MessageEvent):
            msg = '(未支援的事件種類： {})'.format(event)
        elif isinstance(event.message,
                        (ImageMessage, VideoMessage, AudioMessage)):
            msg = self.get_attachment_message(event)
        elif not isinstance(event.message, TextMessage):
            msg = '(未支援的訊息種類： {})'.format(event.message)
        else:
            msg = event.message.text


    def log_event(self, bot_user, event):
        if self.is_not_registered(bot_user):
            return

        event_dict = json.loads(str(event))

        if isinstance(event, MessageEvent):
            ChatMessage.objects.create(
                bot_user=bot_user,
                message=event_dict['message'],
                to_user=False,
            )
            return

        event_dict.pop('replyToken', None)
        LineEvent.objects.create(
            bot_user=bot_user,
            event_type=event.type,
            data=event_dict,
        )
    

    def is_not_registered(self, bot_user):
        return isinstance(bot_user, UnregisteredFakeUser)

class ClientEventHandler(BaseEventHandler):
    line_channel_type = 'client'

    def init_bot_user(self, line_uid):
        bot_user = business_misc.init_bot_user(
            line_uid=line_uid, channel_type=self.line_channel_type,
            fake=True)
        return bot_user

    def get_bot_user(self, line_uid):
        return business_misc.init_bot_user(
           line_uid=line_uid, channel_type=self.line_channel_type,
            create=True)