from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse, Http404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core import serializers
from django.db.models import Q

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import NotFound

from .forms import UploadFileForm
from .models import UserData, SyncData, Sharing

from datetime import datetime
from dateutil.parser import parse

import json, os, hashlib

@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def sync_data_list(request):
    items = serializers.serialize('json', request.user.syncdata_set.all())
    return JsonResponse({'items':items})

@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def user(request, pk):
    user = User.objects.get(pk=pk)
    items = serializers.serialize('json', user.syncdata_set.all())
    return JsonResponse({'items':items})

@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def user_list(request):
    users = []
    for s in Sharing.objects.filter(follower__pk=request.user.pk):
        users.append({'pk': s.owner.pk, 'username': s.owner.username})

    return JsonResponse({'items':users})

@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def sharing_list(request):
    items = []
    for user in User.objects.all().exclude(pk=request.user.pk).order_by('username'):
        items.append({'pk':user.pk, 
                     'username':user.username, 
                     'sharing':request.user.sharing_owners.filter(follower__pk=user.pk).count()})

    return JsonResponse({'items': items})

@api_view(['POST', 'DELETE'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def follower(request, pk):
    if request.method == 'DELETE':
        request.user.sharing_owners.filter(follower__pk=int(pk)).delete()
        return JsonResponse({'success': True})
    elif request.method == 'POST' and request.user.sharing_owners.filter(follower__pk=int(pk)).count() == 0:
        follower = User.objects.get(pk=int(pk))
        s = Sharing(owner=request.user, follower=follower)
        s.save()
        return JsonResponse({'success': True})

    raise Http404('Not found')

@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def download_user_data(request, pk, name):
    if Sharing.objects.filter(follower__pk=request.user.pk, owner__pk=int(pk)).count() == 0:
        raise NotFound()
    try:
        user = User.objects.get(pk=pk)
        sync_data = user.syncdata_set.get(name=name)
        response = HttpResponse(sync_data.file, content_type='application/etipitaka')
        response['Content-Disposition'] = 'attachment; filename="%s"' % (sync_data.file.name.split('/')[-1])
        response['Content-Length'] = sync_data.file.size
        return response
    except SyncData.DoesNotExist:
        raise NotFound()

@api_view(['POST'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def upload_sync_data(request):
    if len(request.FILES) > 0 and request.POST.get('timestamp'):
        platform = request.POST.get('platform', 'ios')
        checksums = []
        for k in request.FILES:
            afile = request.FILES.get(k)
            filename = afile.name
            path = '%s/%s/%s' % (request.user.username, platform, filename)
            queryset = request.user.syncdata_set.filter(name=filename, platform=platform)
            for item in queryset:
                if os.path.exists(item.file.path):
                    os.remove(item.file.path)
            queryset.delete()

            created_at = parse(request.POST.get('timestamp'))

            sync_data = SyncData(file=afile, 
                                 platform=platform, user=request.user, 
                                 name=filename,
                                 created_at=created_at)
            sync_data.save()

            # Calculate MD5 checksum
            sync_data.checksum = hashlib.md5(open(sync_data.file.path, 'rb').read()).hexdigest()
            sync_data.save()
            checksums.append({filename: sync_data.checksum})

        return JsonResponse({'success': True, 'checksums': checksums})
    else:
        return JsonResponse({'success': False})

@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def download_sync_data(request, name):
    try:
        sync_data = request.user.syncdata_set.get(name=name)
        response = HttpResponse(sync_data.file, content_type='application/etipitaka')
        response['Content-Disposition'] = 'attachment; filename="%s"' % (sync_data.file.name.split('/')[-1])
        response['Content-Length'] = sync_data.file.size
        return response
    except SyncData.DoesNotExist:
        raise NotFound()

@api_view(['POST'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def upload_view(request):
    form = UploadFileForm(request.POST, request.FILES)
    if form.is_valid():
        platform = None
        filename = request.FILES['file'].name
        if filename.endswith('.json.etz') or filename.endswith('.json'):
            platform = 'ios'
        elif filename.endswith('.etz'):
            platform = 'pc'
        elif filename.endswith('.js'):
            platform = 'android'

        path = '%s/%s/%s' % (request.user.username, platform, filename)
        queryset = request.user.userdata_set.filter(file=path, platform=platform, deleted=False)
        if queryset.count() > 0:
            return JsonResponse({'file_exists': True})

        queryset = request.user.userdata_set.filter(file=path, platform=platform, deleted=True)
        if queryset.count() > 0:
            for item in queryset:
                if os.path.exists(item.file.path):
                    os.remove(item.file.path)

        user_data = UserData(file=request.FILES['file'], platform=platform, user=request.user)
        user_data.save()        
        return JsonResponse({'success': True, 'pk': user_data.pk})            
    else:
        return JsonResponse({'success': False})

@api_view(['GET', 'DELETE'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def user_data_action(request, pk):
    if request.method == 'DELETE':
        try:
            user_data = request.user.userdata_set.get(pk=pk)
            if os.path.exists(user_data.file.path):
                os.remove(user_data.file.path)
            user_data.deleted = True
            user_data.save()
            return JsonResponse({'success': True, 'pk': str(pk)})
        except UserData.DoesNotExist:
            return JsonResponse({'success': False})
    elif request.method == 'GET':
        try:
            user_data = request.user.userdata_set.get(pk=pk)

            if user_data.deleted:
                raise NotFound()

            if user_data.file.name.endswith('.etz'):
                response = HttpResponse(user_data.file, content_type='application/etipitaka')
            else:
                response = HttpResponse(user_data.file, content_type='text/json')
            response['Content-Disposition'] = 'attachment; filename="%s"' % (user_data.file.name.split('/')[-1])
            response['Content-Length'] = user_data.file.size
            return response
        except UserData.DoesNotExist:
            raise NotFound()

    raise Http404('Unsupport operation')

@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def user_data_list(request):
    deleted = True if request.GET.get('deleted') is not None else False
    items = serializers.serialize('json', request.user.userdata_set.filter(deleted=deleted))
    return JsonResponse({'items': items})
                
@login_required
def user_data_view(request):
    return render(request, 'user_data.html', {})

def index_view(request):
    if request.user.is_authenticated:
        return HttpResponseRedirect('/user_data/')
    return render(request, 'index.html', {})

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user) 
                return HttpResponseRedirect('/')
            else:
                return render(request, 'login.html', {'disabled_account': True})
        else:
            return render(request, 'login.html', {'invalid_login': True})

    context = {}
    if request.GET.get('email'):
        context['confirm_email'] = True
    return render(request, 'login.html', context)
