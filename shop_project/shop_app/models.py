from django.db import models

class Product(models.Model):
    title = models.CharField(max_length=255)
    seller = models.CharField(max_length=255)
    price = models.CharField(max_length=255)
    valid_until = models.CharField(max_length=255)
    note = models.CharField(max_length=255)
    category = models.CharField(max_length=255)

    def __str__(self):
        return self.title