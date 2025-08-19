from django.contrib import admin
from scarabe.models import Account ,Material ,Vehicle ,Tool ,Malfunction ,MalfunctionPhoto ,Advertisement , Reservation , PreCheck , SupportReply , SupportTicket ,SupportAttachment , Notification

# Register your models here.
admin.site.register(Account)
admin.site.register(Material)
admin.site.register(Vehicle)
admin.site.register(Tool)
admin.site.register(Malfunction)
admin.site.register(MalfunctionPhoto)
admin.site.register(Advertisement)
admin.site.register(Reservation)
admin.site.register(PreCheck)
admin.site.register(SupportTicket)
admin.site.register(SupportReply)
admin.site.register(SupportAttachment)
admin.site.register(Notification)