'''
Get alerts from threatstack and pass to csv
'''
import argparse
import datetime
import csv
import os
import requests

API_ENDPOINT = 'https://app.threatstack.com/api/v1/alerts'

TIMESTAMP_FIELDS = ['created_at', 'expires_at', 'last_updated_at']
def format_timestamps(alert):
    '''
    Convert timestamps into times
    '''
    for field in TIMESTAMP_FIELDS:
        if field in alert:
            alert[field] = datetime.datetime.strptime(alert[field], '%Y-%m-%dT%H:%M:%S.%fZ')
            alert[field] = datetime.datetime.strftime(alert[field], '%Y-%m-%d %H:%M:%S')
    return alert

def include_alert(alert, args):
    '''
    Determine whether alert should be included
    Return True if included, False otherwise
    '''
    title = alert.get('title')
    if not title:
        return True
    if args.startswith:
        return title.startswith(args.startswith)
    if args.contains:
        return args.contains in title
    return True

def get_alerts(args):
    '''
    Query api for alerts
    '''
    data = {'fields': args.fields, 'start': args.start, 'end': args.end, 'count': args.count}
    headers = {'Authorization': args.auth, 'Organization': args.org}
    resp = requests.get(API_ENDPOINT, params=data, headers=headers)
    if resp.status_code == 200:
        filename = args.out
        if filename[0] != '/':
            filename = os.getcwd() + filename
        with open(filename, 'wb') as csvfile:
            fieldnames = args.fields.split(',')
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if not args.omitheader:
                writer.writeheader()
            for alert in resp.json():
                if include_alert(alert, args):
                    alert = format_timestamps(alert)
                    writer.writerow(alert)
            print "Successfully wrote values to {}".format(args.out)
    else:
        print "Error querying api: {}".format(resp.text)


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description='Query threatstack alerts.')
    PARSER.add_argument('--auth', help='authentication token', dest='auth', required=True)
    PARSER.add_argument('--org', help='organization', dest='org', required=True)
    PARSER.add_argument('--fields', help='the fields to return from the api', dest='fields',
                        required=False, default='severity,last_updated_at,title')
    PARSER.add_argument('--start', help='start date', dest='start',
                        required=False,
                        default=datetime.datetime.utcnow() - datetime.timedelta(days=1))
    PARSER.add_argument('--end', help='end date', dest='end',
                        required=False,
                        default=datetime.datetime.utcnow())
    PARSER.add_argument('--count', help='number of alerts to return', dest='count',
                        required=False,
                        default=20)
    PARSER.add_argument('--outfile',
                        help='the name (or path including csv) of the csv file to output',
                        dest='out',
                        required=False,
                        default=os.getcwd()+'/'+'alerts.csv')
    PARSER.add_argument('--omitheader', action='store_true', default=False, dest='omitheader')
    FILTER = PARSER.add_mutually_exclusive_group()
    FILTER.add_argument('--startswith',
                        help='filter to titles that start with this string',
                        dest='startswith',
                        required=False,
                        default=None)
    FILTER.add_argument('--contains',
                        help='filter to titles that contain with this string',
                        dest='contains',
                        required=False,
                        default=None)

    ARGS = PARSER.parse_args()

    get_alerts(ARGS)
