# -*- coding: utf-8 -*-
from django import forms
from django.utils.translation import gettext_lazy as _


class UploadFileForm(forms.Form):
    title = forms.CharField(max_length=50)
    file = forms.FileField(
        label=_('Select a file'),
        help_text=_('max. 2 megabytes')
    )
