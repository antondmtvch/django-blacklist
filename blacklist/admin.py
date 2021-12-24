from django.contrib import admin

from .models import Rule, IPWhitelist


class RuleAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'address', 'prefixlen', 'created', 'duration', 'is_active', 'whitelisted')
    list_filter = ('created', 'duration', 'whitelisted')
    search_fields = ('user__username', 'address', 'comments')


class IPWhitelistAdmin(admin.ModelAdmin):
    list_display = ('address', 'prefixlen')
    search_fields = ('address', 'prefixlen')


admin.site.register(Rule, RuleAdmin)
admin.site.register(IPWhitelist, IPWhitelistAdmin)