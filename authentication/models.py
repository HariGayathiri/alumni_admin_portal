from django.db import models

# Create your models here.

class AdminUser(models.Model):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)

    def __str__(self):
        return self.email

# models.py in authentication app
from django.db import models

class Alumni(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField()
    degree = models.CharField(max_length=255)
    department = models.CharField(max_length=255)
    graduationYear = models.IntegerField()
    enrollmentDetails = models.TextField()

    def __str__(self):
        return self.name

from django.db import models

class Survey(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    poll_question = models.CharField(max_length=255)
    options = models.JSONField()
    uploaded_file = models.FileField(upload_to='uploads/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


from django.db import models

class Newsletter(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    image_url = models.URLField(max_length=500)
    created_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

from django.db import models
from django.utils.timezone import now
from datetime import timedelta

class AdminOTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return now() > self.created_at + timedelta(minutes=10)

    def __str__(self):
        return f"{self.email} - {self.otp}"
