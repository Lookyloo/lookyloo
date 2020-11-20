from lookyloo.lookyloo import Lookyloo
import calendar
import datetime

lookyloo = Lookyloo()

stats = {}

for uuid in lookyloo.capture_uuids:
    cache = lookyloo.capture_cache(uuid)
    if 'timestamp' not in cache:
        continue
    date = datetime.datetime.fromisoformat(cache['timestamp'].rstrip('Z'))
    if date.year not in stats:
        stats[date.year] = {}
    if date.month not in stats[date.year]:
        stats[date.year][date.month] = {'analysis': 0, 'redirects': 0}
    stats[date.year][date.month]['analysis'] += 1
    stats[date.year][date.month]['redirects'] += len(cache['redirects'])


for year, data in stats.items():
    print('Year:', year)
    yearly_analysis = 0
    yearly_redirects = 0
    for month in sorted(data.keys()):
        stats = data[month]
        print('   ', calendar.month_name[month])
        print("\tNumber of analysis :", stats['analysis'])
        print("\tNumber of redirects :", stats['redirects'])
        yearly_analysis += stats['analysis']
        yearly_redirects += stats['redirects']

    print("    Sum analysis:", yearly_analysis)
    print("    Sum redirects:", yearly_redirects)
