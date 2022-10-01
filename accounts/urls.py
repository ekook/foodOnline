from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('register_user', views.register_user, name='register_user')
]
