# Generated by Django 4.2.20 on 2025-04-24 08:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('threat_intelligence', '0002_aiclassifiermodel_model_params_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='threatintelentry',
            name='metadata',
            field=models.JSONField(blank=True, default=dict, help_text='Additional metadata in JSON format'),
        ),
        migrations.AddField(
            model_name='threatintelentry',
            name='misp_attribute_id',
            field=models.CharField(blank=True, help_text='MISP Attribute ID', max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='threatintelentry',
            name='misp_event_id',
            field=models.CharField(blank=True, help_text='MISP Event ID', max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='threatintelentry',
            name='stix_id',
            field=models.CharField(blank=True, help_text='STIX ID for the object', max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='threatintelsource',
            name='config',
            field=models.JSONField(blank=True, default=dict, help_text='Additional configuration parameters in JSON format'),
        ),
        migrations.AlterField(
            model_name='threatintelentry',
            name='entry_type',
            field=models.CharField(choices=[('ip', 'IP Address'), ('ip_range', 'IP Range'), ('country', 'Country Code'), ('asn', 'Autonomous System Number'), ('domain', 'Domain Name'), ('hash', 'File Hash'), ('other', 'Other'), ('indicator', 'STIX Indicator'), ('threat_actor', 'STIX Threat Actor'), ('malware', 'STIX Malware'), ('attack_pattern', 'STIX Attack Pattern'), ('campaign', 'STIX Campaign'), ('vulnerability', 'STIX Vulnerability')], max_length=20),
        ),
        migrations.AlterField(
            model_name='threatintelsource',
            name='source_type',
            field=models.CharField(choices=[('ip_list', 'IP Blocklist'), ('vpn_ips', 'VPN IP Addresses'), ('cloud_ips', 'Cloud Provider IPs'), ('botnet', 'Botnet Tracker'), ('geo_block', 'Geographic Blocklist'), ('custom', 'Custom Source'), ('taxii', 'TAXII Feed'), ('misp', 'MISP Instance'), ('stix', 'STIX File/Feed')], max_length=20),
        ),
    ]
