from django.urls import path
from .views import load_csv_data , RegisterView ,CustomTokenObtainPairView, RefreshTokenView ,UpdateProfileView ,UserProfileView ,PasswordChangeView

urlpatterns = [
    path('api/csv-data/', load_csv_data, name='csv-data'),
    path('register/', RegisterView.as_view(), name='register'),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    path('api/update-profile/', UpdateProfileView.as_view(), name='update-profile'),
    path('api/user-profile/', UserProfileView.as_view(), name='user-profile'),
    path('api/change-password/', PasswordChangeView.as_view(), name='change-password'),
]