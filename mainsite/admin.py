from django.contrib import admin

# Register your models here.
from api.models import *
# Register your models here.

admin.site.site_header = '無盡冒險 後台'
admin.site.site_title = 'Line Hero'

# Register your models here.
admin.site.register(LineBotUser)
admin.site.register(Job)
admin.site.register(Player)