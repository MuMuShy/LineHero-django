from django.shortcuts import render, HttpResponse
import logging

from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from linebot import (
    WebhookParser
)
from linebot.exceptions import (
    InvalidSignatureError
)
from lib.line import ClientLineChannel
from lib.webhook import BaseEventHandler,ClientEventHandler

logger = logging.getLogger(__name__)

class BaseCallbackView(View):
    line_channel_class = None
    event_handler_class = None

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        assert self.line_channel_class
        assert self.event_handler_class

        headers = request.headers
        signature = headers['X-Line-Signature']

        body = request.body.decode()

        line_channel = self.line_channel_class()

        parser = WebhookParser(line_channel.secret)

        try:
            events = parser.parse(body, signature)
        except InvalidSignatureError:
            return HttpResponse('Bad Request', 400)

        handler = self.event_handler_class(request)
        for event in events:
            handler.handle_event(event)
        
        return HttpResponse('ok')

class CallbackView(BaseCallbackView):
    line_channel_class = ClientLineChannel
    event_handler_class = ClientEventHandler



def home(request):
    from datetime import datetime
    return render(request, 'test.html', {
        'current_time': str(datetime.now()),
    })