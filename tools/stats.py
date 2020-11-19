from lookyloo.lookyloo import Lookyloo
import calendar
import datetime
 
lookyloo = Lookyloo()
scraped = lookyloo.capture_uuids
 
date = datetime.datetime.now()
year = date.year
 
for i in range(2020,year+1):
  count_year=0
  redirects_year=0
  print (i)
  for j in range(1,12):
    count=0
    redirects=0
    redir=0
    for k in scraped:
      cached = lookyloo.capture_cache(k)
      try:
        if cached['timestamp'].startswith(str(i)+"-"+str('{:02d}'.format(j))):
          count+=1
          try :
            redir+=len(cached['redirects'])
          except:
            print('oup')
      except:
        pass
    print(calendar.month_name[j])
    print("Number of analysis :  "+str(count))
    print("Number of redirects : "+str(redir))
    redirects_year+=redir
    count_year+=count
  print("Total of analysis for year "+str(i)+" :  "+str(count_year))
  print("Total of redirects for year "+str(i)+" : "+str(redirects_year))
