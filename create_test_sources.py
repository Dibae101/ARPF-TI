#!/usr/bin/env python
import os
import django
import requests
import json
from datetime import timedelta
from django.utils import timezone

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'arpf_ti.settings')
django.setup()

from threat_intelligence.models import ThreatIntelSource, ThreatIntelEntry
from threat_intelligence.fetcher import threat_intel_fetcher

def create_test_sources():
    """Create test threat intelligence sources and sample entries."""
    print("Creating test threat intelligence sources...")
    
    # 1. AbuseIPDB - a real blocklist service
    abuseipdb, created = ThreatIntelSource.objects.update_or_create(
        name="AbuseIPDB Blocklist",
        defaults={
            'description': "A blocklist of IPs reported for abusive behavior",
            'source_type': 'ip_list',
            'url': 'https://api.abuseipdb.com/api/v2/blacklist',
            'api_key': 'yourapikey',  # You would use a real API key in production
            'is_active': True,
            'update_frequency': 86400,  # Daily updates
        }
    )
    print(f"Created {'new ' if created else ''}source: {abuseipdb.name}")
    
    # 2. Feodo Tracker Botnet C&C IPs - real botnet tracker
    feodo, created = ThreatIntelSource.objects.update_or_create(
        name="Feodo Tracker Botnet C&C",
        defaults={
            'description': "Tracks Feodo (Emotet, Dridex) botnet command & control servers",
            'source_type': 'botnet',
            'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
            'is_active': True,
            'update_frequency': 43200,  # Twice daily
        }
    )
    print(f"Created {'new ' if created else ''}source: {feodo.name}")
    
    # 3. VPN IP Database - simulated VPN IP database
    vpn_db, created = ThreatIntelSource.objects.update_or_create(
        name="VPN Exit Nodes Database",
        defaults={
            'description': "Database of known VPN exit nodes",
            'source_type': 'vpn_ips',
            'url': 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt',
            'is_active': True,
            'update_frequency': 86400,  # Daily updates
        }
    )
    print(f"Created {'new ' if created else ''}source: {vpn_db.name}")
    
    # 4. Geographic Blocklist for high-risk countries
    geo_block, created = ThreatIntelSource.objects.update_or_create(
        name="High-Risk Countries Blocklist",
        defaults={
            'description': "Blocklist for countries with high cyber attack origins",
            'source_type': 'geo_block',
            'url': 'https://example.com/geo-blocklist',  # This is a fake URL
            'is_active': True,
            'update_frequency': 604800,  # Weekly updates
        }
    )
    print(f"Created {'new ' if created else ''}source: {geo_block.name}")
    
    # 5. AWS IP Ranges
    aws_ip, created = ThreatIntelSource.objects.update_or_create(
        name="AWS IP Ranges",
        defaults={
            'description': "Amazon Web Services IP address ranges",
            'source_type': 'cloud_ips',
            'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
            'is_active': True,
            'update_frequency': 86400,  # Daily updates
        }
    )
    print(f"Created {'new ' if created else ''}source: {aws_ip.name}")
    
    # 6. Custom TAXII source
    taxii_source, created = ThreatIntelSource.objects.update_or_create(
        name="TAXII Test Feed",
        defaults={
            'description': "Test TAXII feed for STIX data",
            'source_type': 'taxii',
            'url': 'https://cti-taxii.mitre.org/taxii/',
            'is_active': True,
            'update_frequency': 86400,  # Daily updates
            'config': {
                'collection_id': '95ecc380-afe9-11e4-9b6c-751b66dd541e',
                'collection_name': 'Enterprise ATT&CK',
                'taxii_version': '2.1'
            }
        }
    )
    print(f"Created {'new ' if created else ''}source: {taxii_source.name}")

def create_sample_entries():
    """Create sample threat intelligence entries for testing."""
    print("\nCreating sample threat intelligence entries...")
    
    # Find a source to attach entries to
    sources = ThreatIntelSource.objects.all()
    if not sources.exists():
        print("No sources found. Please run create_test_sources() first.")
        return
    
    # Use the first available source
    source = sources.first()
    
    # Sample IP addresses (some known malicious IPs)
    sample_ips = [
        "185.220.101.33",  # Tor exit node
        "95.216.145.1",
        "193.36.119.95",
        "23.129.64.102",
        "108.61.122.88",
    ]
    
    # Sample IP ranges
    sample_ranges = [
        "45.95.168.0/24",
        "23.129.64.0/24",
        "185.220.100.0/22",
        "103.109.124.0/24",
    ]
    
    # Sample country codes for geo-blocking
    sample_countries = ["RU", "KP", "IR", "CN"]
    
    # Add sample IP entries
    for ip in sample_ips:
        entry, created = ThreatIntelEntry.objects.update_or_create(
            source=source,
            entry_type='ip',
            value=ip,
            defaults={
                'category': 'malicious',
                'confidence_score': 0.95,
                'is_active': True,
                'first_seen': timezone.now() - timedelta(days=5),
                'last_seen': timezone.now(),
            }
        )
        print(f"Created {'new ' if created else ''}entry: {entry.value}")
    
    # Add sample IP range entries
    for ip_range in sample_ranges:
        entry, created = ThreatIntelEntry.objects.update_or_create(
            source=source,
            entry_type='ip_range',
            value=ip_range,
            defaults={
                'category': 'suspicious',
                'confidence_score': 0.85,
                'is_active': True,
                'first_seen': timezone.now() - timedelta(days=3),
                'last_seen': timezone.now(),
            }
        )
        print(f"Created {'new ' if created else ''}entry: {entry.value}")
    
    # Add sample country entries
    for country in sample_countries:
        entry, created = ThreatIntelEntry.objects.update_or_create(
            source=source,
            entry_type='country',
            value=country,
            defaults={
                'category': 'high_risk',
                'confidence_score': 0.70,
                'is_active': True,
                'first_seen': timezone.now() - timedelta(days=10),
                'last_seen': timezone.now(),
            }
        )
        print(f"Created {'new ' if created else ''}entry: {entry.value}")

def trigger_fetches():
    """Manually trigger fetches for all sources to populate data."""
    print("\nManually triggering data fetches for all sources...")
    sources = ThreatIntelSource.objects.filter(is_active=True)
    
    for source in sources:
        print(f"Fetching data for {source.name}...")
        # Create sample data directly since some URLs aren't real or accessible
        if source.source_type == 'ip_list':
            create_ip_list_entries(source)
        elif source.source_type == 'vpn_ips':
            create_vpn_entries(source)
        elif source.source_type == 'geo_block':
            create_country_entries(source)
        elif source.source_type == 'botnet':
            create_botnet_entries(source)
        elif source.source_type == 'cloud_ips':
            create_cloud_entries(source)
        
        # Update the last_updated timestamp
        source.last_updated = timezone.now()
        source.save()
        print(f"Updated last_updated timestamp for {source.name}")

def create_ip_list_entries(source):
    """Create sample IP list entries for a source."""
    sample_ips = [
        "45.227.255.206", "45.132.192.41", "89.38.98.114", 
        "190.211.254.193", "172.94.119.214", "141.98.81.165"
    ]
    
    for ip in sample_ips:
        entry, created = ThreatIntelEntry.objects.update_or_create(
            source=source,
            entry_type='ip',
            value=ip,
            defaults={
                'category': 'malicious',
                'confidence_score': 0.92,
                'is_active': True,
                'first_seen': timezone.now() - timedelta(days=random.randint(1, 30)),
                'last_seen': timezone.now(),
            }
        )
        print(f"Created {'new ' if created else ''}entry: {entry.value}")

def create_vpn_entries(source):
    """Create sample VPN IP entries."""
    sample_vpn_ips = [
        "185.93.1.115", "165.231.210.171", "198.8.94.170", 
        "104.200.138.39", "196.196.53.124", "5.62.18.71"
    ]
    
    for ip in sample_vpn_ips:
        entry, created = ThreatIntelEntry.objects.update_or_create(
            source=source,
            entry_type='ip',
            value=ip,
            defaults={
                'category': 'vpn',
                'confidence_score': 0.95,
                'is_active': True,
                'first_seen': timezone.now() - timedelta(days=random.randint(1, 15)),
                'last_seen': timezone.now(),
            }
        )
        print(f"Created {'new ' if created else ''}entry: {entry.value}")

def create_country_entries(source):
    """Create sample country code entries."""
    sample_countries = ["RU", "KP", "IR", "CN", "VE", "SY", "SD", "MM"]
    
    for country in sample_countries:
        entry, created = ThreatIntelEntry.objects.update_or_create(
            source=source,
            entry_type='country',
            value=country,
            defaults={
                'category': 'high_risk',
                'confidence_score': 0.75,
                'is_active': True,
                'first_seen': timezone.now() - timedelta(days=30),
                'last_seen': timezone.now(),
            }
        )
        print(f"Created {'new ' if created else ''}entry: {entry.value}")

def create_botnet_entries(source):
    """Create sample botnet entries."""
    sample_botnet_ips = [
        {"ip": "198.54.117.212", "botnet": "Emotet"},
        {"ip": "45.147.231.131", "botnet": "Dridex"},
        {"ip": "186.64.67.51", "botnet": "QBot"},
        {"ip": "45.147.230.14", "botnet": "TrickBot"},
        {"ip": "217.12.221.244", "botnet": "BazarLoader"}
    ]
    
    for item in sample_botnet_ips:
        entry, created = ThreatIntelEntry.objects.update_or_create(
            source=source,
            entry_type='ip',
            value=item["ip"],
            defaults={
                'category': item["botnet"],
                'confidence_score': 0.98,
                'is_active': True,
                'first_seen': timezone.now() - timedelta(days=random.randint(1, 10)),
                'last_seen': timezone.now(),
            }
        )
        print(f"Created {'new ' if created else ''}entry: {entry.value} ({item['botnet']})")

def create_cloud_entries(source):
    """Create sample cloud IP range entries."""
    sample_cloud_ranges = [
        {"range": "52.94.76.0/22", "provider": "AWS-EC2"},
        {"range": "35.190.0.0/18", "provider": "GCP"},
        {"range": "40.90.128.0/18", "provider": "Azure"},
        {"range": "13.104.0.0/14", "provider": "Azure"},
        {"range": "34.83.0.0/18", "provider": "GCP"}
    ]
    
    for item in sample_cloud_ranges:
        entry, created = ThreatIntelEntry.objects.update_or_create(
            source=source,
            entry_type='ip_range',
            value=item["range"],
            defaults={
                'category': item["provider"],
                'confidence_score': 1.0,
                'is_active': True,
                'first_seen': timezone.now() - timedelta(days=45),
                'last_seen': timezone.now(),
            }
        )
        print(f"Created {'new ' if created else ''}entry: {entry.value} ({item['provider']})")

if __name__ == "__main__":
    import random
    create_test_sources()
    create_sample_entries()
    trigger_fetches()
    print("\nAll done! You should now have test sources and entries in your database.")
    print("Go to your application to see the threat intelligence data.")