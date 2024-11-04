#Data
import csv
import os
from django.conf import settings
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .serializers import CsvDataSerializer
#User
from rest_framework import generics
from .serializers import UserSerializer
from rest_framework.permissions import AllowAny

from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from rest_framework.serializers import ModelSerializer
from .serializers import UserProfileUpdateSerializer ,PasswordChangeSerializer ,RegisterSerializer
from django.core.exceptions import ValidationError
# Data
@api_view(['GET'])
def load_csv_data(request):
    data = []
    csv_path = os.path.join(settings.BASE_DIR, 'data', 'shop_data.csv')
    
    with open(csv_path, mode='r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            # Premenujeme kľúče podľa serializéra, ak názvy obsahujú medzery
            row['Plati_do'] = row.pop('Plati do', None)
            data.append(row)
    
    serializer = CsvDataSerializer(data=data, many=True)
    serializer.is_valid(raise_exception=True)
    
    return Response(serializer.data)

#User
class UserCreateView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]  # Každý môže vytvoriť účet

from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status

class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == status.HTTP_200_OK:
            refresh_token = response.data['refresh']
            response.set_cookie(
                'refresh_token', 
                refresh_token, 
                httponly=True, 
                secure=True,          # Nastavte na True pre HTTPS v produkcii
                samesite='Lax'         # Nastavte podľa potreby (napr. 'Strict' alebo 'None')
            )
            del response.data['refresh']  # Odstránime refresh token z odpovede
        return response
    

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
        

        

class UserCreateView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        email = request.data.get("email")

        if User.objects.filter(username=username).exists():
            return Response({"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, password=password, email=email)
        user.save()

        # Generovanie JWT tokenov
        refresh = RefreshToken.for_user(user)
        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }, status=status.HTTP_201_CREATED)
        
## nova registracia 
class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()  # Uloží používateľa a vráti ho z `create` metódy serializéra

            # Generovanie JWT tokenov
            refresh = RefreshToken.for_user(user)
            return Response({
                "success": "Registrácia úspešná",
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserProfileSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email']

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        
        serializer = UserProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate

class UpdateProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def validate_password(self, password):
        # Jednoduchá kontrola na zakázané znaky, ktoré by mohli byť nebezpečné
        if any(char in password for char in "<>\"'"):
            raise ValidationError("Password contains invalid characters.")
        return password

    def put(self, request):
        user = request.user
        serializer = UserProfileUpdateSerializer(user, data=request.data, context={'request': request}, partial=True)

        if serializer.is_valid():
            # Overenie hesla a validácia jeho obsahu
            password = request.data.get('password')
            if not password:
                return Response({"error": "Password is required"}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                self.validate_password(password)  # Volanie validačnej funkcie
            except ValidationError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

            if not authenticate(username=user.username, password=password):
                return Response({"error": "Invalid password"}, status=status.HTTP_403_FORBIDDEN)

            # Uložíme len zmenené polia
            if 'email' in serializer.validated_data and serializer.validated_data['email'] == user.email:
                serializer.validated_data.pop('email')
            if 'name' in serializer.validated_data and serializer.validated_data['name'] == user.first_name:
                serializer.validated_data.pop('name')

            if not serializer.validated_data:
                return Response({"error": "No changes detected."}, status=status.HTTP_400_BAD_REQUEST)

            serializer.save()
            return Response({"success": "Profile updated successfully"}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUES)
    
    
class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"success": "Heslo bolo úspešne zmenené."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)