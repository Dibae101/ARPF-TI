# Generated by Django 4.2.20 on 2025-04-23 04:20

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AIClassifierModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('model_type', models.CharField(choices=[('random_forest', 'Random Forest'), ('naive_bayes', 'Naive Bayes'), ('neural_network', 'Neural Network'), ('gpt', 'GPT-based Model'), ('custom', 'Custom Model')], max_length=20)),
                ('description', models.TextField(blank=True, null=True)),
                ('file_path', models.CharField(help_text='Path to the model file', max_length=255)),
                ('is_active', models.BooleanField(default=True)),
                ('accuracy', models.FloatField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='ThreatIntelSource',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True, null=True)),
                ('source_type', models.CharField(choices=[('ip_list', 'IP Blocklist'), ('vpn_ips', 'VPN IP Addresses'), ('cloud_ips', 'Cloud Provider IPs'), ('botnet', 'Botnet Tracker'), ('geo_block', 'Geographic Blocklist'), ('custom', 'Custom Source')], max_length=20)),
                ('url', models.URLField(help_text='URL for fetching the threat intelligence data')),
                ('api_key', models.CharField(blank=True, help_text='API key if required for access', max_length=255, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('last_updated', models.DateTimeField(blank=True, null=True)),
                ('update_frequency', models.IntegerField(default=86400, help_text='Update frequency in seconds')),
            ],
        ),
        migrations.CreateModel(
            name='ThreatIntelEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('entry_type', models.CharField(choices=[('ip', 'IP Address'), ('ip_range', 'IP Range'), ('country', 'Country Code'), ('asn', 'Autonomous System Number'), ('domain', 'Domain Name'), ('hash', 'File Hash'), ('other', 'Other')], max_length=20)),
                ('value', models.CharField(help_text='The actual value to block or monitor', max_length=255)),
                ('category', models.CharField(blank=True, help_text='Category of the threat', max_length=255, null=True)),
                ('confidence_score', models.FloatField(default=1.0, help_text='Confidence score (0.0 to 1.0)')),
                ('first_seen', models.DateTimeField(auto_now_add=True)),
                ('last_seen', models.DateTimeField(auto_now=True)),
                ('is_active', models.BooleanField(default=True)),
                ('source', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='entries', to='threat_intelligence.threatintelsource')),
            ],
            options={
                'verbose_name_plural': 'Threat intelligence entries',
                'unique_together': {('source', 'entry_type', 'value')},
            },
        ),
    ]
