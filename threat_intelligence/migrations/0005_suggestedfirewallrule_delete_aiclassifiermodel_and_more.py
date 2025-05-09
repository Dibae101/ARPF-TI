# Generated by Django 5.2 on 2025-04-28 19:14

import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('threat_intelligence', '0004_firewallrule'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='SuggestedFirewallRule',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('rule_type', models.CharField(choices=[('ip', 'IP Address'), ('path', 'Request Path'), ('user_agent', 'User Agent'), ('country', 'Country'), ('combination', 'Combination')], max_length=20)),
                ('pattern', models.CharField(help_text='The pattern to match (IP, path, etc.)', max_length=255)),
                ('description', models.TextField(help_text='AI-generated description of why this rule was suggested')),
                ('confidence', models.IntegerField(default=0, help_text='AI confidence level (0-100)')),
                ('attack_type', models.CharField(blank=True, max_length=100, null=True)),
                ('status', models.CharField(choices=[('pending', 'Pending Review'), ('approved', 'Approved'), ('auto_approved', 'Auto-Approved'), ('rejected', 'Rejected')], default='pending', max_length=20)),
                ('source_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('request_path', models.CharField(blank=True, max_length=255, null=True)),
                ('user_agent', models.TextField(blank=True, null=True)),
                ('country', models.CharField(blank=True, max_length=100, null=True)),
                ('additional_data', models.JSONField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('reviewed_at', models.DateTimeField(blank=True, null=True)),
                ('reviewed_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='reviewed_rules', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.DeleteModel(
            name='AIClassifierModel',
        ),
        migrations.DeleteModel(
            name='FirewallRule',
        ),
        migrations.AlterModelOptions(
            name='threatintelsource',
            options={'ordering': ['name'], 'verbose_name_plural': 'Threat intelligence sources'},
        ),
        migrations.AddField(
            model_name='threatintelsource',
            name='api_auth_method',
            field=models.CharField(choices=[('header', 'API Key in Header'), ('parameter', 'API Key as URL Parameter'), ('basic', 'Basic Authentication'), ('none', 'No Authentication')], default='header', help_text='Authentication method for custom API', max_length=20),
        ),
        migrations.AddField(
            model_name='threatintelsource',
            name='api_headers',
            field=models.JSONField(blank=True, default=dict, help_text='Custom headers for API requests'),
        ),
        migrations.AddField(
            model_name='threatintelsource',
            name='api_params',
            field=models.JSONField(blank=True, default=dict, help_text='Default URL parameters for API requests'),
        ),
        migrations.AddField(
            model_name='threatintelsource',
            name='created_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='threatintelsource',
            name='misp_event_limit',
            field=models.IntegerField(default=100, help_text='Maximum number of MISP events to fetch'),
        ),
        migrations.AddField(
            model_name='threatintelsource',
            name='misp_verify_ssl',
            field=models.BooleanField(default=True, help_text='Verify SSL certificate for MISP connection'),
        ),
        migrations.AddField(
            model_name='threatintelsource',
            name='password',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='threatintelsource',
            name='taxii_collection_id',
            field=models.CharField(blank=True, help_text='ID of the TAXII collection', max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='threatintelsource',
            name='taxii_collection_name',
            field=models.CharField(blank=True, help_text='Name of the TAXII collection', max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='threatintelsource',
            name='username',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='threatintelsource',
            name='api_key',
            field=models.CharField(blank=True, help_text='API key if required', max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='threatintelsource',
            name='config',
            field=models.JSONField(blank=True, default=dict, help_text='Additional configuration parameters'),
        ),
        migrations.AlterField(
            model_name='threatintelsource',
            name='name',
            field=models.CharField(max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='threatintelsource',
            name='source_type',
            field=models.CharField(choices=[('taxii', 'TAXII Server'), ('misp', 'MISP Instance'), ('stix', 'STIX Files'), ('custom', 'Custom API'), ('ip_list', 'IP Blocklist'), ('vpn_ips', 'VPN IP Addresses'), ('cloud_ips', 'Cloud Provider IPs'), ('botnet', 'Botnet Tracker'), ('geo_block', 'Geographic Block List')], max_length=20),
        ),
        migrations.AlterField(
            model_name='threatintelsource',
            name='update_frequency',
            field=models.IntegerField(default=3600, help_text='Update frequency in seconds'),
        ),
        migrations.AlterField(
            model_name='threatintelsource',
            name='url',
            field=models.URLField(help_text='URL of the threat intelligence feed'),
        ),
        migrations.AddIndex(
            model_name='suggestedfirewallrule',
            index=models.Index(fields=['rule_type'], name='threat_inte_rule_ty_9b7dc2_idx'),
        ),
        migrations.AddIndex(
            model_name='suggestedfirewallrule',
            index=models.Index(fields=['status'], name='threat_inte_status_cb27d1_idx'),
        ),
        migrations.AddIndex(
            model_name='suggestedfirewallrule',
            index=models.Index(fields=['confidence'], name='threat_inte_confide_9c407e_idx'),
        ),
    ]
