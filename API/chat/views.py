import json

from django.shortcuts import get_object_or_404
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseNotFound, QueryDict
from django.views.generic import View
from .utils import datetime_to_timestamp
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib.sessions.models import Session

from .models import Channel, Message
from .forms import MessageCreationForm, MessagePatchForm, UserPatchForm, SessionPostForm


class MessageView(View):
    def post(self, request, channel_name, *args, **kwargs):
        channel = get_object_or_404(Channel, name=channel_name)

        form = MessageCreationForm(request.POST)

        if not form.is_valid():
            return HttpResponseBadRequest(str(form.errors))

        form.channel = channel
        message = form.save()

        return HttpResponse(message.id)

    def patch(self, request, channel_name, *args, **kwargs):
        qdict = QueryDict(request.body)

        form = MessagePatchForm(qdict)

        if not form.is_valid():
            return HttpResponseBadRequest(str(form.errors))

        form.save()

        return HttpResponse(status=204)

    def get(self, request, channel_name, *args, **kwargs):
        lim = request.GET.get('lim', 100)

        channel = get_object_or_404(Channel, name=channel_name)

        messages = Message.objects.values(
            'text', 'username', 'datetime_start', 'typing', 'id', 'datetime_sent'
        ).filter(channel=channel).order_by('-id')[:lim]

        # convert datetime_start to UTC epoch milliseconds
        for message in messages:
            message['datetime_start'] = datetime_to_timestamp(message['datetime_start'])
            if message['datetime_sent']:
                message['datetime_sent'] = datetime_to_timestamp(message['datetime_sent'])

        messages_json = json.dumps(list(messages))

        return HttpResponse(messages_json, content_type='application/json')

    def delete(self, request, channel_name, *args, **kwargs):
        qdict = QueryDict(request.body)

        if 'id' not in qdict:
            return HttpResponseBadRequest()

        message = get_object_or_404(Message, pk=qdict['id'])

        message.delete()

        return HttpResponse(status=204)


class ChannelView(View):
    def post(self, request, *args, **kwargs):
        channel = Channel(name=request.POST['name'])
        channel.save()

        return HttpResponse(status=204)

    def get(self, request, *args, **kwargs):
        queryset = Channel.objects.values('name')
        channel = get_object_or_404(queryset, name=request.GET['name'])

        return HttpResponse(
            json.dumps(channel),
            content_type='application/json'
        )

class SessionView(View):
    def post(self, request, *args, **kwargs):
        form = SessionPostForm(request.POST)

        if not form.is_valid():
            return HttpResponseBadRequest(str(form.errors))

        if User.objects.filter(username=request.POST['username']).exists():
            user = User.objects.get(username=request.POST['username'])

            if user.has_usable_password():
                if request.POST.get('password') is None:
                    return HttpResponse(
                        status=403,
                        reason='password_required'
                    )

                if check_password(request.POST['password']):
                    return HttpResponse(status=200)

                return HttpResponse(
                    status=403,
                    reason='wrong_password'
                )

            return HttpResponse(
                status=403,
                reason='username_reserved'
            )

        if request.POST.get('password'):
            return HttpResponse(status=422)

        request.session['username'] = request.POST['username']
        user = User.objects.create_user(request.POST['username'])
        user.save()

        return HttpResponse(status=200, reason=request.session.session_key)

    def delete(self, request, *args, **kwargs):
        session = Session.objects.get(session_key=request.session.session_key)
        uid = session.get_decoded().get('_auth_user_id')
        user = User.objects.get(pk=uid)

        user.delete()
        request.session.flush()

class UserView(View):
    def patch(self, request, username, *args, **kwargs):
        if request.session.get('username') != username:
            return HttpResponse(status=403)

        arguments = dict(request.POST)
        arguments.update({'username': username})

        form = UserPatchForm(arguments)

        if not form.is_valid():
            return HttpResponseBadRequest(str(form.errors))

        user = User.objects.get(username=username)
        user.update(**form.cleaned_data)

        return HttpResponse(status=200)
