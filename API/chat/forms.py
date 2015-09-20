import time

from django import forms
from .models import Message
from .utils import timestamp_to_datetime, datetime_to_timestamp


class MessageCreationForm(forms.Form):
    text = forms.CharField(widget=forms.Textarea)
    username = forms.CharField(max_length=20)
    datetime_start = forms.IntegerField()
    typing = forms.BooleanField(required=False)

    def clean_datetime_start(self):
        now = int(round(time.time() * 1000))
        timestamp = int(self.data['datetime_start'])
        if now < timestamp:
            timestamp = now

        self.cleaned_data['datetime_start'] = timestamp_to_datetime(timestamp)

    def save(self):
        self.clean_datetime_start()

        message = Message.objects.create(channel=self.channel, **self.cleaned_data)

        if not message.typing:
            message.datetime_sent = message.datetime_start
            message.save()

        return message;

class UserPatchForm(forms.Form):
    password = forms.CharField(required=False)
    email = forms.EmailField(required=False)

    def save(self):
        session = Session.objects.get(session_key=request.session.session_key)
        uid = session.get_decoded().get('_auth_user_id')
        user = User.objects.get(pk=uid)

        for arg in ['email', 'password']:
            if self.cleaned_data[arg].exists():
                setattr(user, arg, self.cleaned_data[arg])

        user.save()

        return user

class SessionPostForm(forms.Form):
    username = forms.CharField(max_length=20)
    password = forms.CharField(required=False)

class MessagePatchForm(forms.Form):
    id = forms.IntegerField()
    text = forms.CharField(widget=forms.Textarea)
    datetime_sent = forms.IntegerField()
    typing = forms.BooleanField(required=False)

    def is_valid(self):
        if not super(MessagePatchForm, self).is_valid():
            return False

        message = Message.objects.get(pk=self.cleaned_data['id'])
        if not message.typing:
            return False

        return True

    def save(self):
        message = Message.objects.get(pk=self.cleaned_data['id'])

        timestamp_start = datetime_to_timestamp(message.datetime_start)
        timestamp_sent = int(self.cleaned_data['datetime_sent'])

        if timestamp_sent < timestamp_start:
            timestamp_sent = timestamp_start

        message.datetime_sent = timestamp_to_datetime(timestamp_sent)
        message.text = self.cleaned_data['text']
        message.typing = self.cleaned_data.get('typing', False)

        message.save()

        return message
