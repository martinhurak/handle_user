'''
#Data
import csv
import os
from django.conf import settings
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .serializerss import CsvDataSerializer
#User
from rest_framework import generics
from .serializerss import UserSerializer
from rest_framework.permissions import AllowAny

from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from rest_framework.serializers import ModelSerializer
from .serializerss import UserProfileUpdateSerializer ,PasswordChangeSerializer ,RegisterSerializer
from django.core.exceptions import ValidationError


# reset hesla 
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.urls import reverse
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
    
    
class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Generovanie JWT tokenov
            refresh = RefreshToken.for_user(user)
            response = Response({
                "success": "Registrácia úspešná",
                "access": str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)
            
            # Nastavenie refresh tokenu ako HttpOnly cookie
            response.set_cookie(
                'refresh_token',
                str(refresh),
                httponly=True,
                secure=True,  # Nastaviť na True pre produkčné prostredie s HTTPS
                samesite='Lax'
            )
            return response
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        response = Response({"detail": "Successfully logged out"}, status=status.HTTP_200_OK)
        print(response)
        # Odstránenie refresh tokenu z cookies nastavením exspirácie do minulosti
        response.delete_cookie('refresh_token')
        
        return response
    
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
                print(serializer.validated_data)
            if 'username' in serializer.validated_data and serializer.validated_data['username'] == user.username:
                
                serializer.validated_data.pop('username')
            
            if not serializer.validated_data:
                return Response({"error": "No changes detected."}, status=status.HTTP_400_BAD_REQUEST) 
                

            serializer.save()
            return Response({"success": "Profile updated successfully"}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"success": "Heslo bolo úspešne zmenené."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#reset pwd

class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            token = PasswordResetTokenGenerator().make_token(user)
            reset_url = request.build_absolute_uri(
                reverse('password-reset-confirm', args=[user.pk, token])
            )
            send_mail(
                'Obnovenie hesla',
                f'Kliknite na nasledujúci odkaz pre obnovenie hesla: {reset_url}',
                'noreply@example.com',
                [email],
                fail_silently=False,
            )
            return Response({"success": "E-mail s odkazom na obnovenie hesla bol odoslaný."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "Tento e-mail nie je registrovaný."}, status=status.HTTP_400_BAD_REQUEST)
class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Neplatný odkaz na obnovenie hesla."}, status=status.HTTP_400_BAD_REQUEST)

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            return Response({"error": "Neplatný alebo exspirovaný token."}, status=status.HTTP_400_BAD_REQUEST)

        new_password = request.data.get("new_password")
        user.set_password(new_password)
        user.save()
        return Response({"success": "Heslo bolo úspešne zmenené."}, status=status.HTTP_200_OK)
    
 # delete account    
class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        password = request.data.get("password")

        # Overenie hesla
        user = authenticate(username=request.user.username, password=password)
        if user is None:
            return Response({"error": "Nesprávne heslo"}, status=status.HTTP_403_FORBIDDEN)

        # Vymazanie účtu
        request.user.delete()
        return Response({"success": "Účet bol úspešne vymazaný"}, status=status.HTTP_204_NO_CONTENT)
        '''