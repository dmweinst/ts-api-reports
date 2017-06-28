'''
Get alerts from threatstack and pass to csv
'''
import argparse
import datetime
import csv
import os
import requests
import re

API_ENDPOINT = 'https://app.threatstack.com/api/v1/alerts'

TIMESTAMP_FIELDS = ['created_at', 'expires_at', 'last_updated_at']

def main():
    '''
    Main method. Collect command line arguments, and pass them into the get_alerts method
    '''
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
    PARSER.add_argument('--filters', help = 'filters to apply', dest = 'filters', required = False)
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
    if ARGS.filters:
        ARGS.filters = ARGS.filters.split(' and ')

    get_alerts(ARGS)

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
    #This is a legacy section of code
    # title = alert.get('title')
    # if not title:
    #     return
    # if args.startswith:
    #     return title.startswith(args.startswith)
    # if args.contains:
    #     return args.contains in title
    # return True

    #The default state of whether an alert matches is True
    #If we find a reason for the alert not to match, this value will be set to false
    matches_filter = True

    #Iterate over each of the filters that were passed in
    if args.filters:
        for raw_filter in args.filters:
            #Split each of the filters apart
            split_filter = raw_filter.split()

            #The final argument in the list may include spaces. This section will condense all elements of position [2] and greater
            split_filter[2] = ' '.join(split_filter[2:])
            split_filter = split_filter[:3]

            #Filters should take the form of "field" , "operator", "value".
            #This section of code assumes that is the case, and references the values of "split_value" accordingly
            field = split_filter[0]
            operator = split_filter[1]
            value = split_filter[2]

            #Sometimes, the "value" field will contain multiple spaces in a row
            #This causes issues with our comparison
            #Therefore, we're going to replace all instances of multiple spaces with a single space
            alert[field] = re.sub('\s+', ' ', alert[field])
            print(operator)

            if operator == "=":
                if not equals_filter(alert, field, value):
                    matches_filter = False

    return matches_filter


def equals_filter(alert, field, value):
    '''
    This method is called when a filter uses the "equals" operator
    '''
    #The default state of "match" is True
    match = True

    #If the field specified doesn't exist in the JSON, we're going to treat it as not matching
    if not field in alert:
        match = False
    #If the field specified DOES exist in the JSON, we'll check to see if its value matches the specified value
    elif not (alert[field] == value):
        match = False
    return match

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
        with open(filename, 'w') as csvfile:
            fieldnames = args.fields.split(',')
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if not args.omitheader:
                writer.writeheader()
            for alert in resp.json():
                if include_alert(alert, args):
                    alert = format_timestamps(alert)
                    writer.writerow(alert)
            print("Successfully wrote values to " + args.out)
    else:
        print("Error querying api: " + resp.text)


if __name__ == '__main__':
    main()
