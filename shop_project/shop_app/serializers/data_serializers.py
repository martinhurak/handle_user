from rest_framework import serializers
class CsvDataSerializer(serializers.Serializer):
    Názov = serializers.CharField(max_length=255)
    Predajca = serializers.CharField(max_length=255)
    Cena = serializers.CharField(max_length=50)
    Plati_do = serializers.CharField(max_length=50)
    Poznamka = serializers.CharField(max_length=255, allow_blank=True)
    Kategoria = serializers.CharField(max_length=100)