# Generated by Django 5.0.2 on 2024-02-18 16:13

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Product',
            fields=[
                ('id', models.BigIntegerField(primary_key=True, serialize=False, unique=True)),
                ('name', models.CharField(max_length=250)),
                ('category', models.CharField(max_length=250)),
                ('subcategory', models.CharField(max_length=250)),
                ('price', models.IntegerField()),
                ('description', models.CharField(max_length=500)),
            ],
            options={
                'db_table': 'product_info',
            },
        ),
    ]
