'''
Get data from threatstack and pass to csv
'''
import argparse
import datetime
import csv
import io
import json
import os
import requests
import re
from urllib.request import urlopen
from urllib.error import HTTPError

def main():
    '''
    Main method. Collect command line arguments, and pass them into the get_data method
    '''
    parser = argparse.ArgumentParser(description='Query threatstack API.')
    parser.add_argument('--auth', help='authentication token', dest='auth', required=True)
    parser.add_argument('--org', help='organization', dest='org', required=True)
    parser.add_argument('--fields', help='the fields to return from the api', dest='fields',
                        required=True)
    parser.add_argument('--outfile',
                        help='the name (or path including csv) of the csv file to output',
                        dest='out',
                        required=False,
                        default=os.getcwd()+'/'+'data.csv')
    parser.add_argument('--omitheader', action='store_true', default=False, dest='omitheader')
    parser.add_argument('--filters', help = 'filters to apply', dest = 'filters', required = False)
    parser.add_argument('--api-version', help = 'The version of the TS API to query', dest = 'api_version', required = False,
                        choices = ['v1', 'v2'],  default = 'v2')
    parser.add_argument('--endpoint', help = 'The endpoint to query', dest = 'endpoint', required = True)
    parser.add_argument('--slack', help = 'Whether to post the CSV report to Slack', dest = 'slack',
                        required = False, default = False)

    args = parser.parse_args()
    if args.filters:
        args.filters = args.filters.split(' and ')

    get_data(args)

def include_data(data, args):
    '''
    Determine whether data should be included
    Return True if included, False otherwise
    '''

    #The default state of whether data matches is True
    #If we find a reason for the data not to match, this value will be set to false
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

            #Sometimes, "data[field]" will contain multiple spaces in a row
            #This causes issues with our comparison
            #Therefore, we're going to replace all instances of multiple spaces with a single space
            if field in data:
                data[field] = re.sub('\s+', ' ', str(data[field]))

            #The user is allowed to dot seperate "field", which denotes they want to filter on sub-layers of "data"
            #Therefore, before we pass field and data into the appropriate filter, we're going to redefine them to reflect the appropriate level
            field = field.split('.')
            local_data = data
            for level in field:
                if level == '[]':
                    local_data = local_data[0]
                else:
                    if local_data.get(level):
                        local_data = local_data[level]
                    else:
                        matches_filter = False
                        break

            #At this point, "local_data" should be set to the actual value that we wish to compare
            #We'll use it as a parameter for the filter functions
            #We're only going to run the comparison if matches_filter is still true. Otherwise, we'll just skip to the return
            if matches_filter == True:
                if operator == "=":
                    if not equals_filter(local_data, value):
                        matches_filter = False

                elif operator == "like":
                    if not like_filter(local_data, value):
                        matches_filter = False

                elif operator == "starts_with":
                    if not starts_with_filter(local_data, value):
                        matches_filter = False

                elif operator == "ends_with":
                    if not ends_with_filter(local_data, value):
                        matches_filter = False

    return matches_filter


def equals_filter(data, value):
    '''
    This method is called when a filter uses the "=" operator
    '''
    #The default state of "match" is True
    match = True

    #If the field specified DOES exist in the JSON, we'll check to see if its value matches the specified value
    if not (data == value):
        match = False
    return match

def like_filter(data, value):
    '''
    This method is called when a filter uses the "like" operator
    '''
    #The default state of "match" is True
    match = True

    #If the field specified DOES exist in the JSON, we'll check to see if its value matches the specified value
    if not (value in data):
        match = False
    return match

def starts_with_filter(data, value):
    '''
    This method is called when a filter uses the "starts_with" operator
    '''
    #The default state of "match" is True
    match = True

    #If the field specified DOES exist in the JSON, we'll check to see if its value matches the specified value
    #print(data)
    if not (data.startswith(value)):
        match = False
    return match

def ends_with_filter(data, value):
    '''
    This method is called when a filter uses the "ends_with" operator
    '''
    #The default state of "match" is True
    match = True

    #If the field specified DOES exist in the JSON, we'll check to see if its value matches the specified value
    if not (data.endswith(value)):
        match = False
    return match

def filter_data(data, fields):
    #We're going to build the filtered_data object and return it
    filtered_data = {}
    #Split fieldnames by commas, which gives a list of each field that we wish to return
    fieldnames = fields.split(',')
    #Iterate over each of the fields from fieldnames
    for field in fieldnames:
        #We're going to be manipulating the value "field", but we want a clean copy of it to build into the response
        return_field = field
        #Split fields by dots, which denote levels in the JSON that the user wishes to filter to
        field = field.split('.')
        #local_data is a copy of the data variable. We'll continually reassign its value as we iterate
        #This is to allow us to track our position within the original JSON
        local_data = data
        #Iterate over each level in the field specified by the user
        for level in field:
            if level == '[]':
                local_data = local_data[0]
            else:
                #If the current level exists in our current position in the JSON object
                if local_data.get(level):
                    #Reassign local_data to the value of "level" in the object
                    local_data = local_data[level]
                #If at any time we don't find the correct field, not it and break out
                else:
                    print('Could not find field',level,'in object',local_data)
                    local_data = ''
                    break
        #Replace all commas with semicolons in the data, to avoid confict with CSV data
        local_data = re.sub(',',';',str(local_data))

        #Build up the filtered data to return
        filtered_data[return_field] = local_data
    return filtered_data

def post_to_slack(slack_object):
    slack_url = 'https://hooks.slack.com/services/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'
    slack_message = {
                        'message':'Hello, world!',
                        'channel':'cse-tools'
                    }
    slack_data = {
                     'attachments': [
                         {
                             "fallback": "Required plain-text summary of the attachment.",
                             "color": "#36a64f",
                             "pretext": "",
                             "author_name": "Elastic Worx" ,
                             "author_link": "http://flickr.com/bobby/",
                             "author_icon": "http://flickr.com/icons/bobby.jpg",
                             "title": "EC2 - Cost Summary of All Resources Running ",
                             "title_link": "https://api.slack.com/",
                             "text": slack_message,
                             "mrkdwn_in": ["text"],
                             #"fields": field_data,
                             "image_url": "https://s3.amazonaws.com/securitybuddy/eyes.png",
                             "thumb_url": "https://s3.amazonaws.com/securitybuddy/eyes.png",
                             "footer": "Slack API",
                             "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
                         }
                     ]
                 }

    try:
        urlopen(slack_url, slack_data)
        response.read()
        print('Message successfully posted to', slack_url)
    except HTTPError as e:
        print('Request failed:', e.code, e.reason)

def get_data(args):
    '''
    Query api for data
    '''
    if args.api_version == 'v1':
        api_endpoint = 'https://app.threatstack.com/api/v1/'
        headers = {'Authorization': args.auth, 'Organization': args.org}
    elif args.api_version == 'v2':
        api_endpoint = 'https://api.threatstack.com/v2/'
        headers = {'Authorization': args.auth, 'Organization-id': args.org}
    api_endpoint = api_endpoint + args.endpoint
    resp = requests.get(api_endpoint, headers=headers)
    if resp.status_code == 200:
        filename = args.out
        if filename[0] != '/':
            filename = os.getcwd() + filename
        with open(filename, 'w') as csvfile:
            fieldnames = args.fields.split(',')
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            #We're also writing to a separate object, used to post to Slack if necessary
            slack_object = io.StringIO()
            slack_writer = csv.DictWriter(slack_object, fieldnames = fieldnames)
            if not args.omitheader:
                writer.writeheader()
                slack_writer.writeheader()
            api_response = resp.json()
            #This section is fairly hack-ish
            #We're determining which section of the returned JSON contains the relevant data
            #To do so, we're first checking to see if what we recieved was itself a list, and using that as our data if it is
            #If the data is not a list, we're looking for an element at the top level who's value is of type list
            data = None
            if str(type(api_response)) == "<class 'list'>":
                data = api_response
            else:
                for key in api_response:
                    if str(type(api_response[key])) == "<class 'list'>" :
                        data = api_response[key]
            #Throw an error if we found no value for data
            if not data:
                raise ValueError("Invalid JSON data. Did you query the correct endpoint?")
            #Iterate over the data
            for element in data:
                #include_data returns true or false, based on the filter parameters passed by the user
                if include_data(element, args):
                    #filter_data just returns the fields that the user specified
                    filtered_data = filter_data(element, args.fields)
                    writer.writerow(filtered_data)
                    slack_writer.writerow(filtered_data)
            if args.slack:
                post_to_slack(slack_object)
            print("Successfully wrote values to " + args.out)
    else:
        print("Error querying api: " + resp.text)


if __name__ == '__main__':
    main()
