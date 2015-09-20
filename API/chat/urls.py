from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt

from . import views

urlpatterns = [
    url(
        r'^messages/(?P<channel_name>[a-zA-Z0-9_.-]+)/$',
        csrf_exempt(views.MessageView.as_view()),
        name='message'
    ),
    url(
        r'^channels/',
        views.ChannelView.as_view(),
        name='channel'
    ),
    url(
        r'^sessions/',
        csrf_exempt(views.SessionView.as_view()),
        name='session'
    ),
    url(
        r'^users/(?P<username>[a-zA-Z0-9_.-]+)/$',
        csrf_exempt(views.UserView.as_view()),
        name='user'
    )
]
