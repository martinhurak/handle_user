# serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

class CsvDataSerializer(serializers.Serializer):
    Názov = serializers.CharField(max_length=255)
    Predajca = serializers.CharField(max_length=255)
    Cena = serializers.CharField(max_length=50)
    Plati_do = serializers.CharField(max_length=50)
    Poznamka = serializers.CharField(max_length=255, allow_blank=True)
    Kategoria = serializers.CharField(max_length=100)
    
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password')

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email']
        )
        user.set_password(validated_data['password'])  # Bezpečné hashovanie hesla
        user.save()
        return user
    

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Tento e-mail je už registrovaný.")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user
    



class UserProfileUpdateSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    name = serializers.CharField(source='first_name', max_length=50, required=True)

    class Meta:
        model = User
        fields = ['name', 'email']

    def validate_email(self, value):
        user = self.context['request'].user
        if value == user.email:
            raise serializers.ValidationError("The new email is the same as the current email.")
        if User.objects.filter(email=value).exclude(id=user.id).exists():
            raise serializers.ValidationError("This email is already registered by another user.")
        return value

    def validate_name(self, value):
        if any(char in value for char in "<>\"'"):
            raise serializers.ValidationError("Invalid characters in name.")
        if len(value.strip()) == 0:
            raise serializers.ValidationError("Name cannot be empty or contain only spaces.")
        return value
    
    
class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Staré heslo je nesprávne.")
        return value

    def validate_new_password(self, value):
        try:
            validate_password(value)  # Použije Django štandardné pravidlá pre heslo
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()