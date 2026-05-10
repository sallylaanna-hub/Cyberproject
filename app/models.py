from django.db import models

# Create your models here.
from django.db import models

class Patient(models.Model):
    name = models.TextField()
    diagnosis = models.TextField()