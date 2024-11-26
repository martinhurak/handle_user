# views/password_views.py

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from django.core.mail import send_mail
from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework import status
from ..serializers.password_serializers import PasswordChangeSerializer


class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"success": "Heslo bolo úspešne zmenené."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

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
    permission_classes = [AllowAny]

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
