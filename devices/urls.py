from django.urls import path
from . import views

urlpatterns = [
    path('', views.device_list, name='device_list'),
    path('approve/<int:device_id>/', views.approve_device, name='approve_device'),
    path('reject/<int:device_id>/', views.reject_device, name='reject_device'),
    path('edit/<int:device_id>/', views.edit_device, name='edit_device'),
]
