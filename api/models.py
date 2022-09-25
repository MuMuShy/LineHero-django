from django.db import models
from django.utils import timezone
from lib.log_changes_mixin import LogChangesMixin
from django.db.models import ForeignKey, SET_NULL, BooleanField, JSONField, \
    OneToOneField
# Create your models here.
UID_LENGTH = 255
UUID_LENGTH = 36
CHAR_FIELD_LIMIT = 255
CHAR_FIELD_LIMIT_SHORT = 16
IDENTITY_CARD_LIMIT = 10
PHONE_NUMBER_LENGTH = 20


class AutoDateTimeField(models.DateTimeField):
    def pre_save(self, model_instance, add):
        return timezone.now()

class RichMenuSetting(models.Model):
    name = models.CharField('Menu 名稱', max_length=CHAR_FIELD_LIMIT,
                            unique=True, db_index=True)
    menu_id = models.CharField('Menu ID', max_length=CHAR_FIELD_LIMIT,
                               db_index=True)
    content_hash = models.CharField('內容 hash 值', max_length=CHAR_FIELD_LIMIT,
                                    default='')

    created_at = models.DateTimeField('建立日期', default=timezone.now)
    updated_at = AutoDateTimeField('修改日期', default=timezone.now)

    class Meta:
        verbose_name = 'Rich Menu 設定'
        verbose_name_plural = verbose_name

    def __str__(self):
        return '#{} {}'.format(self.id, self.name)


class LiffAppSetting(models.Model):
    channel_type = models.CharField('Channel種類', max_length=CHAR_FIELD_LIMIT)
    name = models.CharField('LIFF 名稱', max_length=CHAR_FIELD_LIMIT)
    liff_id = models.CharField('LIFF ID', max_length=CHAR_FIELD_LIMIT,
                               db_index=True)
    content_hash = models.CharField('內容 hash 值', max_length=CHAR_FIELD_LIMIT,
                                    default='')

    created_at = models.DateTimeField('建立日期', default=timezone.now)
    updated_at = AutoDateTimeField('修改日期', default=timezone.now)

    class Meta:
        verbose_name = 'LIFF APP 設定'
        verbose_name_plural = verbose_name
        indexes = [
            models.Index(fields=['channel_type', 'name']),
        ]
        unique_together = [
            ['channel_type', 'name']
        ]

    def __str__(self):
        return '#{} {}'.format(self.id, self.name)


class LineBotUser(LogChangesMixin, models.Model):
    name = models.CharField('姓名/別名', max_length=CHAR_FIELD_LIMIT,
                            null=True, blank=True)
    picture_url = models.CharField('顯圖網址', max_length=CHAR_FIELD_LIMIT,
                                   null=True, blank=True)
    line_uid = models.CharField('Line UID', max_length=UID_LENGTH,
                                db_index=True, default='')
    phone_number = models.CharField('手機', max_length=CHAR_FIELD_LIMIT,
                                    db_index=True, default='', blank=True)
    active_menu = ForeignKey(RichMenuSetting, null=True, on_delete=SET_NULL,blank=True)

    user_type = models.CharField('玩家類型', max_length=CHAR_FIELD_LIMIT,
                                null=True, blank=True)

    following = BooleanField('有追蹤本頻道', default=False)

    created_at = models.DateTimeField('建立日期', default=timezone.now)
    updated_at = AutoDateTimeField('修改日期', default=timezone.now)

    class Meta:
        verbose_name = 'LINE使用者'
        verbose_name_plural = verbose_name

    def __str__(self):
        return '#{} {}'.format(self.id, self.name or '(名稱未知)')

    @classmethod
    def get_model(cls, channel_type):
        return LineBotUser

    @classmethod
    def get_by_type(cls, channel_type, **kwargs):
        return cls.get_model(channel_type).objects.get(**kwargs)

class Job(LogChangesMixin, models.Model):
    name = models.CharField('職業名稱',null=False,blank=False,max_length=CHAR_FIELD_LIMIT)
    class Meta:
        verbose_name = '職業'
        verbose_name_plural = verbose_name

    def __str__(self):
        return '{}'.format(self.name or '(名稱未知)')

class Player(LogChangesMixin, models.Model):
    line_user = models.OneToOneField(LineBotUser,null=True,blank = True,on_delete=models.SET_NULL)
    nick_name = models.CharField('暱稱',null=True,blank=True,max_length=CHAR_FIELD_LIMIT_SHORT)
    money = models.IntegerField('金錢',default=0)
    diamond = models.IntegerField('鑽石',default=0)
    daily_request_done = models.BooleanField('已簽到',default=False)
    job = models.OneToOneField(Job,null=True,blank = True,on_delete=models.SET_NULL)
    class Meta:
        verbose_name = '玩家'
        verbose_name_plural = verbose_name

    def __str__(self):
        return '{}'.format(self.nick_name or self.line_user.name or '未知')


class QueuedLineMessage(models.Model):
    bot_user = ForeignKey(LineBotUser, null=True, on_delete=SET_NULL)
    content = JSONField('內容', null=True, blank=True)
    extra_info = JSONField(null=True, blank=True)
    created_at = models.DateTimeField('建立日期', default=timezone.now)

    class Meta:
        verbose_name = '待發的Line訊息'
        verbose_name_plural = verbose_name

class ChatMessage(models.Model):
    bot_user = ForeignKey(LineBotUser, null=True, on_delete=SET_NULL)
    message = JSONField(null=True, blank=True)
    to_user = BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = '聊天記錄'
        verbose_name_plural = verbose_name

class KeyValueStore(models.Model):
    key = models.CharField(max_length=CHAR_FIELD_LIMIT, db_index=True)
    value = JSONField(null=True, blank=True)
    created_at = models.DateTimeField('建立日期', default=timezone.now)
    updated_at = AutoDateTimeField('修改日期', default=timezone.now)

    @classmethod
    def set(cls, k, v):
        cls.objects.update_or_create(key=k, defaults={'value': v})

    @classmethod
    def get(cls, k):
        try:
            return cls.objects.get(key=k).value
        except cls.DoesNotExist:
            pass

    @classmethod
    def delete_key(cls, k):
        cls.objects.filter(key=k).delete()

    @classmethod
    def pop(cls, k):
        v = cls.get(k)
        cls.delete_key(k)
        return v

class LineEvent(models.Model):
    bot_user = ForeignKey(LineBotUser, null=True, on_delete=SET_NULL)
    event_type = models.CharField(max_length=CHAR_FIELD_LIMIT, blank=True,
                                  db_index=True)
    data = JSONField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)