from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from ..serializers.user_serializers import UserProfileUpdateSerializer ,UserSerializer
from rest_framework_simplejwt.tokens import RefreshToken





class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Získanie údajov profilu používateľa."""
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class UpdateProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        serializer = UserProfileUpdateSerializer(user, data=request.data, context={'request': request}, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({"success": "Profil bol úspešne aktualizovaný."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        """Vymazanie účtu používateľa."""
        password = request.data.get("password")

        if not authenticate(username=request.user.username, password=password):
            return Response({"error": "Nesprávne heslo."}, status=status.HTTP_403_FORBIDDEN)

        request.user.delete()
        return Response({"success": "Účet bol úspešne vymazaný."}, status=status.HTTP_204_NO_CONTENT)
