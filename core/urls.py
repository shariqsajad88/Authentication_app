from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/api/', include('authentication.urls')), 
    path("register/", TemplateView.as_view(template_name="register.html"), name="register"),
    path("login/", TemplateView.as_view(template_name="login.html"), name="login"),
    path("verify-otp/", TemplateView.as_view(template_name="verify_otp.html"), name="verify-otp"),
]
