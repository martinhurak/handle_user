from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from ..serializers.auth_serializers import RegisterSerializer


class RefreshTokenView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return Response({'detail': 'Refresh token missing'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            token = RefreshToken(refresh_token)
            access_token = token.access_token
            return Response({'access': str(access_token)}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'detail': 'Token is invalid or expired'}, status=status.HTTP_401_UNAUTHORIZED)
        

# Funkcie pre prácu s cookies
def set_refresh_token_cookie(response, refresh_token):
    response.set_cookie(
        'refresh_token',
        refresh_token,
        httponly=True,
        secure=True,  # Nastaviť na True v produkcii
        samesite='Lax'
    )

def delete_refresh_token_cookie(response):
    response.delete_cookie('refresh_token')

# Login View
class LoginView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            set_refresh_token_cookie(response, response.data['refresh'])
            del response.data['refresh']  # Odstráni refresh token z tela odpovede
        return response

# Logout View
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        response = Response({"detail": "Successfully logged out"}, status=status.HTTP_200_OK)
        delete_refresh_token_cookie(response)
        return response

# Register View
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()  # Používame metódu `create` zo serializéra

            # Generovanie tokenov
            refresh = RefreshToken.for_user(user)
            response = Response({
                "success": "Registration successful",
                "access": str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)
            
            # Nastavenie refresh tokenu do cookies
            set_refresh_token_cookie(response, str(refresh))
            return response

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
