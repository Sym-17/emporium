from django.db import models

# Create your models here.
class User(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=250, null=False)
    email = models.CharField(max_length=250, null=False)
    password = models.CharField(max_length=250, null =False)

    class Meta:
        db_table = "user_info"
        
