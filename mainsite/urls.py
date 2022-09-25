from django.shortcuts import render, redirect
from django.urls import reverse, path, include
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import RedirectView



from lib import business_misc
from lib.misc import get_liff_context
from . import views
from api.views import CallbackView


def get_view(template_path, channel_type, liff_name=None, extra_context=None):
    def inner(request):
        _extra_context = extra_context

        if callable(_extra_context):
            _extra_context = _extra_context(request)

        _extra_context = _extra_context or {}
        print('get_view', request)
        return render(request, template_path,
                      get_liff_context(channel_type, liff_name,
                                       **_extra_context))

    return inner


def _get_extra_context_for_token(request):
    return {'global_vars': {
        'payment_token': request.GET.get('t'),
        'type': request.GET.get('type')
    }}

def _get_extra_context_for_profile(request):
    return {'global_vars': {
        'raise_credit_url': reverse('raise_credit')
    }}


urlpatterns = [
    path('callback', CallbackView.as_view()),

    path('favicon.ico', RedirectView.as_view(url='/static/favicon.ico')),
    path('', views.home),
]
