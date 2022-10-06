from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('register_user', views.register_user, name='register_user'),
    path('register_vendor', views.register_vendor, name='register_vendor'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('my_account/', views.my_account, name='my_account'),
    path('cust_dashboard/', views.cust_dashboard, name='cust_dashboard'),
    path('vendor_dashboard/', views.vendor_dashboard, name='vendor_dashboard'),
]
