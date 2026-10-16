from django.contrib import admin
from django.urls import path
from sec_app import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.login_view, name='login'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('change-role/', views.change_role_view, name='change_role'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
]