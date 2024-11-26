from django.urls import path
      
from .views.auth_views import LoginView, LogoutView, RegisterView , RefreshTokenView 
from .views.password_views import PasswordChangeView, PasswordResetRequestView, PasswordResetConfirmView
from .views.user_views import UserProfileView, UpdateProfileView, DeleteAccountView

urlpatterns = [
    #token
    path('api/token/refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    #data
    #path('api/csv-data/', load_csv_data, name='csv-data'), # pridaj ked budeš robiť datami 
    #user
    path('api/login/', LoginView.as_view(), name='login'), 
    path('api/logout/', LogoutView.as_view(), name='logout'), 
    path('api/register/', RegisterView.as_view(), name='register'), 
    #account-details
    path('api/change-password/', PasswordChangeView.as_view(), name='change-password'), 
    path('api/password-reset/', PasswordResetRequestView.as_view(), name='password-reset'), # newpwd_reset // dokonči 
    path('api/password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'), # new pwdresetconfirm // dokonči
    path('api/delete-account/', DeleteAccountView.as_view(), name='delete-account'), 
    path('api/update-profile/', UpdateProfileView.as_view(), name='update-profile'),  
    path('api/user-profile/', UserProfileView.as_view(), name='user-profile'), 
   
]

