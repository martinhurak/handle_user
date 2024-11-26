# views/data_views.py

import csv
import os
from django.conf import settings
from rest_framework.response import Response
from rest_framework.decorators import api_view
from ..serializerss.data_serializers import CsvDataSerializer


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