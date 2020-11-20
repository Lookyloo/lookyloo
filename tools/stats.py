from lookyloo.lookyloo import Lookyloo
import calendar
import datetime
from urllib.parse import urlparse

lookyloo = Lookyloo()

stats = {}

today = datetime.date.today()
calendar_week = today.isocalendar()[1]
weeks_stats = {calendar_week - 1: {'analysis': 0, 'uniq_urls': set()},
               calendar_week: {'analysis': 0, 'uniq_urls': set()}}


def uniq_domains(uniq_urls):
    domains = set()
    for url in uniq_urls:
        splitted = urlparse(url)
        domains.add(splitted.hostname)
    return domains


for uuid in lookyloo.capture_uuids:
    cache = lookyloo.capture_cache(uuid)
    if 'timestamp' not in cache:
        continue
    date = datetime.datetime.fromisoformat(cache['timestamp'].rstrip('Z'))
    if date.year not in stats:
        stats[date.year] = {}
    if date.month not in stats[date.year]:
        stats[date.year][date.month] = {'analysis': 0, 'uniq_urls': set()}
    stats[date.year][date.month]['analysis'] += 1
    stats[date.year][date.month]['uniq_urls'].update(cache['redirects'])
    stats[date.year][date.month]['uniq_urls'].add(cache['url'])
    if date.isocalendar()[1] in weeks_stats:
        weeks_stats[date.isocalendar()[1]]['analysis'] += 1
        weeks_stats[date.isocalendar()[1]]['uniq_urls'].update(cache['redirects'])
        weeks_stats[date.isocalendar()[1]]['uniq_urls'].add(cache['url'])

print('Statistics for the last two weeks:')
for week_number, week_stat in weeks_stats.items():
    print(f'Week {week_number}:')
    print('    Number of analysis:', week_stat['analysis'])
    print('    Number of unique URLs:', len(week_stat['uniq_urls']))
    domains = uniq_domains(week_stat['uniq_urls'])
    print('    Number of unique domains:', len(domains))


for year, data in stats.items():
    print('Year:', year)
    yearly_analysis = 0
    yearly_urls = 0
    yearly_domains = 0
    for month in sorted(data.keys()):
        stats = data[month]
        print('   ', calendar.month_name[month])
        print("\tNumber of analysis :", stats['analysis'])
        print('\tNumber of unique URLs:', len(stats['uniq_urls']))
        domains = uniq_domains(stats['uniq_urls'])
        print('\tNumber of unique domains:', len(domains))
        yearly_analysis += stats['analysis']
        yearly_urls += len(stats['uniq_urls'])
        yearly_domains += len(domains)

    print("    Sum analysis:", yearly_analysis)
    print("    Sum unique urls:", yearly_urls)
    print("    Sum unique domains:", yearly_domains)
