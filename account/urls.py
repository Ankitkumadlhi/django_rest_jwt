
from django.urls import path, include
from account.views import *


urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('change-password/', UserChangePasswordView.as_view(), name='change-password'),
    path('send-password-reset/', SendPasswordResetEmailView.as_view(), name='send-password_reset'),
    path('password-reset-confirm/<uid>/<token>/', UserPasswordResetView.as_view(), name='password-reset-confirm'),
]