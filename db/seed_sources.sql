-- ============================================================================
-- Seed: register every requested source with its discovered feed type.
-- feed_type reflects what the collector framework auto-discovers per the
-- "CSV/JSON/XLSX/XML/RSS/API first, HTML scrape only as fallback" rule.
-- Re-run discovery periodically — sites change their feed offerings; the
-- discovery probe (collectors/discovery.py) will flip feed_type automatically
-- and update feed_url when a better feed appears.
-- ============================================================================

INSERT INTO breach_data_sources (slug, name, base_url, category, feed_type, feed_url, requires_api_key, collection_mode, notes) VALUES

-- Ransomware leak-site trackers
('ransomware_live',   'Ransomware.live',         'https://www.ransomware.live',       'ransomware_leak_tracker', 'json_api', 'https://api.ransomware.live/v2/recentvictims', FALSE, 'scheduled', 'Public JSON API; no key required as of last check'),
('ransom_db',         'Ransom-DB',                'https://ransom-db.com',              'ransomware_leak_tracker', 'html_scrape', NULL, FALSE, 'scheduled', 'No public feed discovered; structured table scrape'),
('leakix_ransomware',  'LeakIX — Ransomware',     'https://leakix.net/ransomware',      'ransomware_leak_tracker', 'json_api', 'https://leakix.net/api/ransomware', TRUE, 'scheduled', 'API key required for higher rate limits'),
('hackmanac',          'Hackmanac',                'https://hackmanac.com',              'ransomware_leak_tracker', 'rss', 'https://hackmanac.com/feed/', FALSE, 'scheduled', NULL),

-- State AG breach notification portals
('maine_ag',           'Maine AG — Data Security Breaches', 'https://www.maine.gov/ag/consumer-protection/data-security-breaches', 'state_ag_notification', 'html_scrape', NULL, FALSE, 'scheduled', 'Published as an HTML table; no CSV export found'),
('mass_ag_reports',     'Mass.gov — Breach Notification Reports', 'https://www.mass.gov/lists/data-breach-notification-reports', 'state_ag_notification', 'csv', NULL, FALSE, 'scheduled', 'Annual CSV reports posted; check for new file each run'),
('mass_ag_breaches',    'Mass.gov — Data Breaches',  'https://www.mass.gov/data-breaches', 'state_ag_notification', 'html_scrape', NULL, FALSE, 'scheduled', NULL),
('california_oag',      'California OAG — Data Breach List', 'https://oag.ca.gov/privacy/databreach/list', 'state_ag_notification', 'html_scrape', NULL, FALSE, 'scheduled', 'Sortable HTML table, paginated server-side'),
('vermont_ag',          'Vermont AG — Security Breach Notices', 'https://ago.vermont.gov/focus-areas/data-privacy/security-breach-notices', 'state_ag_notification', 'html_scrape', NULL, FALSE, 'scheduled', NULL),
('oregon_doj',          'Oregon DOJ — Data Breach Notifications', 'https://doj.state.or.us/consumer-protection/data-breach-notifications', 'state_ag_notification', 'html_scrape', NULL, FALSE, 'scheduled', NULL),
('washington_atg',      'Washington AG — Data Breach Notifications', 'https://www.atg.wa.gov/data-breach-notifications', 'state_ag_notification', 'csv', NULL, FALSE, 'scheduled', 'WA publishes an annual breach report CSV/PDF dataset'),
('indiana_ag',          'Indiana AG — Data Breach Notifications', 'https://www.in.gov/attorneygeneral/consumer-protection-division/id-theft-prevention/data-breach-notifications', 'state_ag_notification', 'html_scrape', NULL, FALSE, 'scheduled', NULL),
('montana_doj',         'Montana DOJ — Consumer Data Breach Notices', 'https://dojmt.gov/consumer/data-breach-notices', 'state_ag_notification', 'html_scrape', NULL, FALSE, 'scheduled', NULL),
('delaware_ag',         'Delaware AG — Security Breach Unit', 'https://attorneygeneral.delaware.gov/fraud/cpu/securitybreach', 'state_ag_notification', 'html_scrape', NULL, FALSE, 'scheduled', NULL),
('north_dakota_ag',     'North Dakota AG — Data Breach Notices', 'https://attorneygeneral.nd.gov/consumer-resources/data-breach-notices', 'state_ag_notification', 'html_scrape', NULL, FALSE, 'scheduled', NULL),

-- Federal regulatory
('hhs_ocr_breach_portal', 'HHS OCR Breach Portal',  'https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf', 'federal_regulatory', 'csv', NULL, FALSE, 'scheduled', 'Portal exposes a CSV export of the breach report'),
('hipaa_journal',         'HIPAA Journal — Breach News', 'https://www.hipaajournal.com/category/data-breach-news', 'security_news', 'rss', 'https://www.hipaajournal.com/category/data-breach-news/feed/', FALSE, 'scheduled', NULL),
('sec_edgar_search',      'SEC EDGAR Full-Text Search', 'https://www.sec.gov/edgar/search', 'sec_filing', 'json_api', 'https://efts.sec.gov/LATEST/search-index?q=%22cybersecurity+incident%22&forms=8-K', FALSE, 'scheduled', 'EDGAR full-text search has a documented JSON API; filter on Item 1.05 8-Ks'),
('sec_cyber_disclosures', 'SEC — Cybersecurity Disclosures', 'https://www.sec.gov/corpfin/cybersecurity-disclosures', 'sec_filing', 'html_scrape', NULL, FALSE, 'scheduled', 'Guidance/index page; links resolved and crawled individually'),

-- Security journalism / aggregators
('databreaches_net',  'DataBreaches.net',          'https://databreaches.net',           'security_news', 'rss', 'https://databreaches.net/feed/', FALSE, 'scheduled', NULL),
('bleepingcomputer',  'BleepingComputer',           'https://www.bleepingcomputer.com',   'security_news', 'rss', 'https://www.bleepingcomputer.com/feed/', FALSE, 'scheduled', NULL),
('thedfirreport',     'The DFIR Report',            'https://www.thedfirreport.com',      'security_news', 'rss', 'https://thedfirreport.com/feed/', FALSE, 'scheduled', NULL),
('securityweek',      'SecurityWeek',               'https://www.securityweek.com',       'security_news', 'rss', 'https://www.securityweek.com/feed/', FALSE, 'scheduled', NULL),
('therecord_media',   'The Record',                 'https://therecord.media',            'security_news', 'rss', 'https://therecord.media/feed/', FALSE, 'scheduled', NULL),
('cyberscoop',        'CyberScoop',                 'https://cyberscoop.com',             'security_news', 'rss', 'https://cyberscoop.com/feed/', FALSE, 'scheduled', NULL),
('darkreading',       'Dark Reading',               'https://www.darkreading.com',        'security_news', 'rss', 'https://www.darkreading.com/rss.xml', FALSE, 'scheduled', NULL),

-- Breach lookup / dark-web indexing services (on-demand enrichment only — see notes)
('haveibeenpwned',    'Have I Been Pwned',          'https://haveibeenpwned.com',         'breach_lookup_service', 'json_api', 'https://haveibeenpwned.com/api/v3/breaches', TRUE, 'scheduled', 'The /breaches endpoint IS a legitimate bulk metadata feed (company, date, data classes) with no credential contents — safe to poll on schedule'),
('dehashed',          'DeHashed',                   'https://www.dehashed.com',           'breach_lookup_service', 'json_api', 'https://api.dehashed.com/search', TRUE, 'on_demand_lookup', 'Per-query lookup API. Store ONLY breach-name + date + record-count metadata returned for a queried company/domain. Never persist credential/password fields.'),
('intelx',            'Intelligence X',             'https://intelx.io',                  'breach_lookup_service', 'json_api', 'https://2.intelx.io/intelligent/search', TRUE, 'on_demand_lookup', 'Per-query lookup API. Same data-handling restriction as DeHashed above.'),

-- Nonprofit / chronology trackers
('idtheftcenter',      'ID Theft Center — Data Breach', 'https://www.idtheftcenter.org/data-breach', 'nonprofit_tracker', 'html_scrape', NULL, FALSE, 'scheduled', NULL),
('privacyrights_breaches', 'Privacy Rights Clearinghouse — Data Breaches', 'https://www.privacyrights.org/data-breaches', 'nonprofit_tracker', 'html_scrape', NULL, FALSE, 'scheduled', NULL),
('privacyrights_chronology', 'Privacy Rights Clearinghouse — Chronology', 'https://www.privacyrights.org/consumer-guides/data-breach-chronology', 'nonprofit_tracker', 'csv', NULL, FALSE, 'scheduled', 'Historical chronology offered as a downloadable dataset'),
('enforcementtracker', 'GDPR Enforcement Tracker',  'https://www.enforcementtracker.com', 'eu_uk_regulatory', 'html_scrape', NULL, FALSE, 'scheduled', 'Server-side filterable table; consider their data export option if available'),

-- Government advisories
('cisa_advisories',    'CISA — Cybersecurity Advisories', 'https://www.cisa.gov/news-events/cybersecurity-advisories', 'government_advisory', 'rss', 'https://www.cisa.gov/cybersecurity-advisories/all.xml', FALSE, 'scheduled', NULL),
('cisa_kev',           'CISA — Known Exploited Vulnerabilities', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'government_advisory', 'json_api', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', FALSE, 'scheduled', 'Official JSON feed, updated continuously'),
('ic3',                'FBI IC3',                    'https://www.ic3.gov',                'government_advisory', 'html_scrape', NULL, FALSE, 'scheduled', NULL),

-- EU / UK regulatory
('ico_enforcement',    'ICO — Action We''ve Taken',  'https://ico.org.uk/action-weve-taken', 'eu_uk_regulatory', 'html_scrape', NULL, FALSE, 'scheduled', NULL),
('ncsc_uk',            'NCSC UK',                     'https://www.ncsc.gov.uk',             'eu_uk_regulatory', 'rss', 'https://www.ncsc.gov.uk/api/1/services/news-rss-feed.xml', FALSE, 'scheduled', NULL),
('edpb',               'European Data Protection Board', 'https://edpb.europa.eu',           'eu_uk_regulatory', 'html_scrape', NULL, FALSE, 'scheduled', NULL)
;
