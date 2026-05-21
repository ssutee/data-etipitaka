from django.core.files.uploadedfile import SimpleUploadedFile

from user_data.forms import UploadFileForm


def test_upload_form_valid():
    upload = SimpleUploadedFile('a.json', b'{}', content_type='application/json')
    form = UploadFileForm(data={'title': 'demo'}, files={'file': upload})
    assert form.is_valid()


def test_upload_form_requires_file():
    form = UploadFileForm(data={'title': 'demo'}, files={})
    assert not form.is_valid()
    assert 'file' in form.errors


def test_upload_form_requires_title():
    upload = SimpleUploadedFile('a.json', b'{}', content_type='application/json')
    form = UploadFileForm(data={}, files={'file': upload})
    assert not form.is_valid()
    assert 'title' in form.errors
