from contextlib import contextmanager

import math
import sys
from django.db.models import Q
from django.shortcuts import render
from inspect import getframeinfo, stack

import functools
from os.path import basename, relpath

import datetime
import hashlib
import ipware
import itertools
import json
import logging
import os
import pyotp
import re
import tempfile
import time
import yaml
from datetime import timedelta
from django.conf import settings
from django.core import signing
from django.core.cache import cache
from django.forms import model_to_dict
from django.http import HttpResponse, JsonResponse
from django.template import TemplateDoesNotExist, Template, Context
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.encoding import smart_str
from django.utils.safestring import mark_safe
from django.utils.timezone import localtime
from mimetypes import guess_type
from ratelimit.decorators import ratelimit
from ratelimit.exceptions import Ratelimited
from urllib.parse import urlencode, unquote

from lib.exceptions import ErrorMessageForUser

logger = logging.getLogger(__name__)
_logger = logger

OTP_EXPIRE_INTERVAL = 60 * 10  # OTP 幾秒後過期
OTP_SECRET_BASE32 = 'base32secret323a'  # 隨便一個base32字串

_ENCRYPT_SALT = 'okinawa shio'  # 沖繩鹽

ORIGINAL_FILE_NAME_SEPARATOR = '__'

FILE_SAVE_PATH = settings.ROOT_DATA_DIR_PATH.joinpath('user_upload')

BARCODE_ENCODING_128 = 'code128'
BARCODE_ENCODING_39 = 'code39'

MAX_RETRY_RANDOM_GEN = 10


def md5(data):
    hash_md5 = hashlib.md5()
    if isinstance(data, bytes):
        hash_md5.update(data)
    elif isinstance(data, dict):
        hash_md5.update(json.dumps(data, sort_keys=True).encode())
    else:
        with open(data, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)

    return hash_md5.hexdigest()


def read_yaml(file_path):
    with open(file_path, 'r', encoding="utf-8") as f:
        return yaml.load(f, Loader=yaml.FullLoader)


def load_config(config_rel_path):
    config_dir = settings.ROOT_DIR_PATH.joinpath('config')
    path = config_dir.joinpath('{}'.format(config_rel_path))
    return read_yaml(path)


def today():
    return timezone.localdate()


def now():
    return timezone.localtime()


def localize(dt):
    tz = timezone.get_default_timezone()
    return tz.localize(dt)


def to_tz_naive(dt):
    return localtime(dt).replace(tzinfo=None)



@contextmanager
def capture_exception():
    try:
        yield
    except:
        report_exception()


def report_error_decorator(func):
    def inner(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            report_exception()
            raise

    return inner


def get_or_set_cache(cache_key, generate_value, timeout=60):
    result = cache.get(cache_key)
    if result is None:
        logger.debug('Cached value for key "{}" not found'.format(cache_key))
        result = generate_value() if callable(
            generate_value) else generate_value
        cache.set(cache_key, result, timeout=timeout)
    else:
        logger.debug('Using cached value for key:{}'.format(cache_key))

    return result


def cached(cache_key, timeout=60):
    def decorator(func):
        return lambda: get_or_set_cache(cache_key, func, timeout=timeout)

    return decorator


def get_client_ip(request):
    client_ip, is_routable = ipware.get_client_ip(request)
    if not client_ip or not is_routable:
        return None

    return client_ip


def access_token_required(func):
    def inner(request, *args, **kwargs):
        token = request.META.get('HTTP_ACCESS_TOKEN') or request.GET.get(
            'access_token') or request.GET.get('_t')
        if token != settings.API_ACCESS_TOKEN:
            error = 'No access token' if not token else 'Invalid access token'
            return JsonResponse({
                'error': error,
            }, status=403)

        return func(request, *args, **kwargs)

    return inner


class InvalidPhoneNumber(Exception):
    pass


def to_half_width(full_width_str):
    if not full_width_str:
        return ''

    full = "　０１２３４５６７８９（）－" \
           "ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ" \
           "ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ"
    half = ' 0123456789()-' \
           'ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
           'abcdefghijklmnopqrstuvwxyz'
    assert len(full) == len(half)
    return full_width_str.translate(str.maketrans(full, half))


def canonicalize_phone_number(raw_phone_number):
    # 正規化為 09XXXXXXXX 的格式
    phone_number = to_half_width(raw_phone_number or '').strip()
    phone_number = re.sub("([^\x00-\x7F])+",'',phone_number) #移除所有中文
    phone_number = re.sub("([a-zA-Z])+",'',phone_number) #移除所有英文
    phone_number = re.sub('[() -]', '', phone_number)
    phone_number = re.sub('^09', '9', phone_number)
    phone_number = re.sub('^\+8869', '9', phone_number)
    phone_number = re.sub('[() -]', '', phone_number)
    

    # if re.search('\D', phone_number):
    #     raise InvalidPhoneNumber(
    #         'Invalid number: {}'.format(raw_phone_number)+' '+phone_number)

    return '0' + phone_number


def count_celery_eta(countdown):
    # celery 4.1.0 計算eta有嚴重bug，所以自己算eta比較快
    # https://github.com/celery/celery/pull/4173
    # 可以等4.2.0 https://github.com/celery/celery/issues/4387
    eta = (datetime.datetime.utcnow() + timedelta(
        seconds=countdown)) if countdown else None
    return eta


def text_with_length_limit(text, length_limit):
    if not length_limit or len(text) <= length_limit:
        return text

    ellipsis = '...'

    length_truncated = length_limit - len(ellipsis)
    if length_truncated < 0:
        return ellipsis

    return text[:length_truncated] + ellipsis


def grouper(n, iterable, fillvalue=None, fill=False):
    "grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx"
    # from https://docs.python.org/3/library/itertools.html#itertools-recipes
    args = [iter(iterable)] * n
    groups = list(itertools.zip_longest(fillvalue=fillvalue, *args))
    if not fill:
        groups[-1] = tuple(filter(lambda x: x != fillvalue, groups[-1]))
    return groups


def serve_file(full_file_path, download_filename=''):
    mime_type = guess_type(str(full_file_path))[0] or \
                guess_type(str(download_filename))[0]
    mime_download = 'application/force-download'
    if 'image' not in (mime_type or ''):
        mime_type = mime_download

    # from https://stackoverflow.com/questions/1156246/having-django-serve-downloadable-files
    with open(full_file_path, "rb") as f:
        response = HttpResponse(f.read(), content_type=mime_type)
        if mime_type == mime_download:
            file_name = download_filename or os.path.basename(full_file_path)
            response[
                'Content-Disposition'] = 'attachment; filename=%s' % smart_str(
                file_name)

            response['X-Sendfile'] = smart_str(full_file_path)
        return response


def get_link_html(url, text, target_blank=False):
    attrs = ''
    if target_blank:
        attrs += ' target="_blank"'

    return mark_safe('<a href="{}"{}>{}</a>'.format(url, attrs, text))


def get_liff_context(channel_type, liff_name, global_vars=None,
                     **extra_context):
    from api.models import LiffAppSetting
    liff = LiffAppSetting.objects.get(
        channel_type=channel_type, name=liff_name) if liff_name else None
    js_global_vars = {
        'liff_id': liff.liff_id if liff else None,
    }
    js_global_vars.update(**global_vars or {})
    context = {
        'global_vars': json.dumps(js_global_vars),
    }
    context.update(**extra_context)
    return context


def get_totp(account, interval=OTP_EXPIRE_INTERVAL, **kwargs):
    return pyotp.TOTP(OTP_SECRET_BASE32, interval=interval, name=account,
                      **kwargs)


def common_ajax_decorator(func):
    def inner(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ErrorMessageForUser as e:
            return JsonResponse({
                'success': False,
                'error': str(e),
            })
        except Ratelimited as e:
            return JsonResponse({
                'success': False,
                'error': '請稍候再試',
            }, status=429)

    return inner


def common_liff_decorator(liff_name, channel_type='client'):
    def decorator(func):
        @functools.wraps(func)
        def inner(self, request, *args, **kwargs):
            if request.GET.get('liff.state'):
                return render(request, 'liff/liff_redirect.html',
                              get_liff_context(channel_type, liff_name))

            return func(self, request, *args, **kwargs)

        return inner

    return decorator


def build_url(path, query=None, absolute=False):
    url = (settings.DEFAULT_HOST_URL if absolute else '') + path
    if query:
        url += "?{}".format(urlencode(query))

    return url


def encrypt(value):
    return signing.dumps(value, salt=_ENCRYPT_SALT)


def decrypt(s):
    if not s:
        return None

    return signing.loads(s, salt=_ENCRYPT_SALT)


def validate_non_empty_fields(model):
    empty_fields = [k for k, v in model_to_dict(model).items() if not v]
    model.full_clean(exclude=empty_fields)


def generate_user_file_name(uid, label, ext, prefix='',
                            original_file_name=None, relative=False):
    return generate_general_file_name(
        uid, label, ext, prefix=prefix, original_file_name=original_file_name,
        relative=relative)


def generate_general_file_name(obj, label, ext, prefix='',
                               original_file_name=None, relative=False,
                               dir=''):
    if not isinstance(obj, str):
        assert dir
        uid = '{}/{}'.format(dir, obj.id)
    else:
        uid = obj

    fb_id_str = "{}".format(uid)
    prefix = prefix or '_'.join([
        fb_id_str,
        label,
        "%d" % time.time(),
        ''
    ])
    ext = ext or ''
    ext = '.' + ext if not ext.startswith('.') else ext
    suffix = ext

    if original_file_name:
        original_file_name = basename(original_file_name)
        original_file_name = re.sub('\.[^.]*$', '', original_file_name)
        original_file_name = unquote(original_file_name)

        suffix = '{}{}{}'.format(ORIGINAL_FILE_NAME_SEPARATOR,
                                 original_file_name, ext)

    def is_proper_name(file_name):
        if not original_file_name:
            return True

        split = file_name.split(ORIGINAL_FILE_NAME_SEPARATOR, 1)
        return split[1] == original_file_name + ext

    path = mktemp_if(is_proper_name, prefix=prefix, suffix=suffix,
                     dir=get_user_file_dir(obj))
    if relative:
        path = relpath(path, settings.BASE_DIR)

    return path


def mktemp_if(predicate, *args, **kwargs):
    for i in range(10):
        file_name = tempfile.mktemp(*args, **kwargs)

        if predicate(file_name):
            return file_name

    raise Exception('Unable to create proper name by mktemp')


def get_user_file_dir(psid):
    fb_id_str = "{}".format(psid)
    return os.path.abspath(str(FILE_SAVE_PATH.joinpath(fb_id_str)))


def custom_ratelimit(*args, **kwargs):
    from ratelimit.core import ip_mask

    def user_or_real_ip(group, request):
        if request.user.is_authenticated:
            return str(request.user.pk)

        client_ip = get_client_ip(request)
        return ip_mask(client_ip)

    return ratelimit(*args, key=user_or_real_ip, **kwargs)


def search_and_render_to_string(template_path, context):
    last_exception = None
    for path in [
        template_path,
    ]:
        try:
            return render_to_string(path, context)
        except TemplateDoesNotExist as e:
            last_exception = e

    raise last_exception


def render_template(template_path, context):
    render_result = search_and_render_to_string(template_path, context)
    return mark_safe(render_result)


def convert_to_child_class(obj, child_class):
    attr = {
        obj.__class__._meta.model_name + '_ptr_id': obj.pk
    }
    child = child_class(**attr)
    child.__dict__.update(obj.__dict__)
    child.save()


def nested_get(obj, path, should_raise=False):
    path_list = path.split('.')
    ret = obj
    for i, node in enumerate(path_list):
        try:
            if isinstance(ret, dict):
                ret = ret[node]
            else:
                ret = getattr(ret, node)
        except (KeyError, TypeError, AttributeError):
            if should_raise:
                raise
            else:
                return None

    return ret


def nested_set(obj, path, value, skip_on_error=False):
    path_list = path.split('.')
    for i, node in enumerate(path_list):
        # print(i, obj, path_list, node, value)
        try:
            if i == len(path_list) - 1:
                obj[node] = value
                return
            elif obj.get(node) is None:
                obj[node] = {}
        except TypeError:
            if skip_on_error:
                return

            raise TypeError(
                'nested_set: error setting the path {}. The parent is {}'
                    .format('.'.join(path_list[:i + 1]), obj))

        obj = obj[node]


def merge(target, *args):
    for d in args:
        target.update(d)

    return target


def deep_merge(target, *sources):
    def is_dict(o):
        return isinstance(o, dict)

    for source in sources:
        if not source:
            continue

        for k, v in source.items():
            if k in target and is_dict(target[k]) and is_dict(v):
                deep_merge(target[k], v)
            else:
                target[k] = source[k]

    return target


def render_from_string(template_str, context):
    return Template(template_str).render(Context(context))


def render_message(id, context=None):
    context = context or {}
    msg_dict = load_config('../templates/text/messages.yml')
    template = nested_get(msg_dict, id)
    if not template:
        return render_to_string(
            'text/messages/{}.txt'.format(id.replace('.', '/')), context)

    assert template, 'Message template not found: {}'.format(id)
    return render_from_string(template, context)


def save_as_barcode(s, path, encoding=BARCODE_ENCODING_39):
    from barcode import Code128, Code39
    from barcode.writer import ImageWriter

    if encoding == BARCODE_ENCODING_128:
        code = Code128(s, writer=ImageWriter())
    else:
        code = Code39(s, writer=ImageWriter(), add_checksum=False)

    return code.save(path, {
        'module_height': 8,  # 條碼高度 default: 15
        'text_distance': 2,  # 條碼跟文字間距 default: 5
    })


def date_range(start, end):
    """ 從start到end（含）的所有日期 """
    assert end >= start
    n_days = math.ceil((end - start).days)
    return [(start + datetime.timedelta(days=delta))
            for delta in range(n_days + 1)]


def beginning_of_the_day(dt_or_date=None):
    """
    :param dt_or_date: datetime, date 或 相對於今天的天數 e.g. 0:今天 1:明天　-1: 昨天
    :return:
    """
    try:
        dt_or_date = now() + datetime.timedelta(days=dt_or_date or 0)
    except:
        pass

    tz = timezone.get_default_timezone()
    if isinstance(dt_or_date, datetime.date) and not isinstance(
            dt_or_date, datetime.datetime):
        return localize(datetime.datetime.combine(
            dt_or_date, datetime.datetime.min.time()))
    return dt_or_date.astimezone(tz).replace(hour=0, minute=0, second=0,
                                             microsecond=0)


def tz_date_filter(field, dt):
    start = beginning_of_the_day(dt)
    end = beginning_of_the_day(dt + timedelta(days=1))

    return Q(**{field + '__range': (start, end)})


def render_message_page(request, msg):
    return render(request, 'liff/message.html', {'message': msg})


def get_file_ext(path):
    ext = os.path.splitext(path)[1]
    return ext


def is_image_ext(path):
    return (get_file_ext(path or '')).lower().replace(
        '.', '') in ['jpg', 'gif', 'png', 'bmp', 'jpeg']


def generate_without_duplicate(gen_func, model, field,
                               max_retry=MAX_RETRY_RANDOM_GEN):
    candidates = {gen_func() for _ in range(max_retry)}
    conditions = {
        field + '__in': candidates
    }
    candidates -= set(model.objects.filter(**conditions).values(field))
    if not candidates:
        raise Exception('產生 uid 失敗')

    return candidates.pop()


def is_admin(user):
    return user.is_staff and user.is_active


def beginning_of_week(dt, first_day_of_week=1):
    day = beginning_of_the_day(dt)
    shift_days = (day.isoweekday() - first_day_of_week) % 7
    return day - datetime.timedelta(days=shift_days)



