'''
Get alerts from threatstack and pass to csv
'''
import argparse
import datetime
import csv
import os
import requests

API_ENDPOINT = 'https://app.threatstack.com/api/v1/alerts'

'''
severity
last_updated_at
title
'''
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
            writer.writeheader()
            for alert in resp.json():
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

    ARGS = PARSER.parse_args()

    get_alerts(ARGS)
