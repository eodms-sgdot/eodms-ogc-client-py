##############################################################################
# MIT License
# 
# Copyright (c) 2020 Her Majesty the Queen in Right of Canada, as 
# represented by the President of the Treasury Board
# 
# Permission is hereby granted, free of charge, to any person obtaining a 
# copy of this software and associated documentation files (the "Software"), 
# to deal in the Software without restriction, including without limitation 
# the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the 
# Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in 
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
# DEALINGS IN THE SOFTWARE.
# 
##############################################################################

import sys
import os
import requests
from xml.etree import ElementTree
import base64
import urllib.request
from urllib.parse import urlencode
from urllib.parse import urlparse
import argparse
import datetime
import time
import math
import traceback
import re
import getpass
import urllib.parse
import json

import common

RAPI_DOMAIN = 'https://www.eodms-sgdot.nrcan-rncan.gc.ca'

def download_image(url, session, dest_fn):
    
    auth = session.auth
    
    user = auth[0]
    pwd = auth[1]
    
    pass_man = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    pass_man.add_password(None, url, user, pwd)
    authhandler = urllib.request.HTTPBasicAuthHandler(pass_man)
    opener = urllib.request.build_opener(authhandler)
    urllib.request.install_opener(opener)
    
    urllib.request.urlretrieve(url, dest_fn)

def run(session, in_fn):
    '''
    Runs the process for downloading images already ordered
        using the eodms-order.py script.
        
    @type  in_fn: str
    @param in_fn: The input filename of the OrderInfo file created by running
                    the eodms-order.py script.
    '''
    
    # Open OrderInfo CSV file and grab the header
    orderinfo_csv = open(in_fn, 'r')
    orderinfo_lines = common.get_lines(orderinfo_csv)
    
    orderinfo_header = orderinfo_lines[0].split(',')
    orderinfo_header = [h.strip('\n') for h in orderinfo_header]
    
    # Check for columns in input file
    if 'Record ID' not in orderinfo_header or \
        'Collection ID' not in orderinfo_header or \
        'Order ID' not in orderinfo_header or \
        'Order Item ID' not in orderinfo_header:
        err_msg = '''The input file does not contain the proper columns.
  The input file must contain the following columns:
    Record ID
    Collection ID
    Order ID
    Order Item ID''' 
        common.print_support(err_msg)
        sys.exit(1)
    
    # Extract image info from CSV file
    images = []
    for l in orderinfo_lines[1:len(orderinfo_lines)-3]:
        vals = l.split(',')
        img = {}
        for idx, h in enumerate(orderinfo_header):
            img[h] = vals[idx].strip('\n')
        
        images.append(img)
    
    # Query the RAPI for all order information for the current user
    query = '%s/wes/rapi/order' % RAPI_DOMAIN
    order_res = common.send_query(query, session)
    order_json = order_res.json()
    
    img_orders = []
    
    # Extract the ordered images from the order results
    for i in images:
        record_id = i['Record ID']
        collection_id = i['Collection ID']
        order_id = i['Order ID']
        orderitem_id = i['Order Item ID']
        
        order_items = order_json['items']
        for o in order_items:
            # If the order ID and record ID in the order results
            #   matches the image's order ID and record ID
            if int(order_id) == int(o['orderId']) and \
                int(record_id) == int(o['recordId']):
                img_orders.append(o)
                
    if len(img_orders) == 0:
        # If no orders could be found
        print("\nNo orders could be found.")
        print("Exiting Script.")
        return None
    
    success_orders = []
    
    # For each image, if the status is AVAILABLE_FOR_DOWNLOAD, 
    #   download the image, otherwise print a message
    for img in img_orders:
        
        # Get the variables from the image order results
        record_id = img['recordId']
        order_id = img['orderId']
        orderitem_id = img['itemId']
        status = img['status']
        status_msg = img['statusMessage']
        
        # Get the email address of the user, if applicable
        email = ''
        if 'NOTIFICATION_EMAIL_ADDRESS' in img['parameters'].keys():
            email = img['parameters']['NOTIFICATION_EMAIL_ADDRESS']
        
        # If the status is AVAILABLE_FOR_DOWNLOAD, download the image
        if status == 'AVAILABLE_FOR_DOWNLOAD':
            # Get the list of destinations
            dests = img['destinations']
            download_paths = []
            for d in dests:
                print("d: %s" % d)
                
                # Get the string value of the destination
                str_val = d['stringValue']
                str_val = str_val.replace('</br>', '')
                
                # Parse the HTML text of the destination string
                root = ElementTree.fromstring(str_val)
                url = root.text
                fn = os.path.basename(url)
                
                if not os.path.exists('downloads'):
                    os.mkdir('downloads')
                
                # Download the image
                print("\nDownloading link for Record ID %s: %s" % \
                        (record_id, url))
                # resp = session.get(url)
                
                # # Save the image contents to the 'downloads' folder
                out_fn = "downloads\\%s" % fn
                full_path = os.path.realpath(out_fn)
                # out_f = open(out_fn, 'wb')
                # full_path = os.path.realpath(out_f.name)
                # #print("full_path: %s" % full_path)
                # out_f.write(resp.content)
                # out_f.close()
                
                download_image(url, session, out_fn)
                
                # Record the URL and downloaded file to a dictionary
                dest_info = {}
                dest_info['url'] = url
                dest_info['local_destination'] = full_path
                download_paths.append(dest_info)
                
                resp = None
                
            img['destinations'] = download_paths
            
            # Add the image to a list of successful orders
            success_orders.append(img)
        else:
            if status == 'CANCELLED' or status == 'FAILED' or \
                status == 'EXPIRED' or status == 'DELIVERED' or \
                status == 'MEDIA_ORDER_SUBMITTED':
                
                print("\nCannot download order item (Record ID %s, " \
                        "Order ID %s, Order Item ID %s)." % (record_id, \
                        order_id, orderitem_id))
                        
                if status == 'CANCELLED':
                    # If status is CANCELLED, print a statement
                    print("The order item has been Cancelled.")
                    
                elif status == 'FAILED':
                    # If status is FAILED, print the reason and mention 
                    #   they've received an email
                    print("The order item has Failed due to the following " \
                            "issue:")
                    print('    %s' % status_msg)
                    print('An "EODMS Image Request Failed Notification" ' \
                            'email with more information should have ' \
                            'been sent to %s.' % email)
                    print("Please check your emails for the notification.")
                    
                elif status == 'EXPIRED':
                    # If status is EXPIRED, print a statement
                    print("The order item has Expired.")
                    
                elif status == 'DELIVERED':
                    # If status is DELIVERED, inform user they've received 
                    #   an email
                    print("An email should have been sent to %s with " \
                            "information/instructions on how to access " \
                            "your order." % email)
                    print("Please check your emails for the notification.")
                            
                elif status == 'MEDIA_ORDER_SUBMITTED':
                    # If status is MEDIA_ORDER_SUBMITTED, inform user they've
                    #   received an email
                    print("An email should have been sent to %s with " \
                            "information/instructions on how to access " \
                            "your order." % email)
                    print("Please check your emails for the notification.")    
            else:
                # If any other status, let the user know that the order is 
                #   processing and to check their emails for a notification
                print("\nCannot download order item (Record ID %s, Order " \
                        "ID %s, Order Item ID %s) at this time." % \
                        (record_id, order_id, orderitem_id))
                print("The status of the order item is %s." % status)
                print("You should receive an email sent to %s when your " \
                        "order is ready." % email)
                print("Please check your emails for an EODMS Image Request " \
                    "Delivery Notification email and then re-run this script.")
    
    if len(success_orders) > 0:
        # Print information for all successful orders
        #   including the download location
        print("\nThe following images have been downloaded:")
        for o in success_orders:
            rec_id = o['recordId']
            order_id = o['orderId']
            orderitem_id = o['itemId']
            dests = o['destinations']
            for d in dests:
                loc_dest = d['local_destination']
                src_url = d['url']
                print("\nRecord ID %s" % rec_id)
                print("    Order Item ID: %s" % orderitem_id)
                print("    Order ID: %s" % order_id)
                print("    Downloaded File: %s" % loc_dest)
                print("    Source URL: %s" % src_url)
            
def main():
    
    try:

        parser = argparse.ArgumentParser(description='Download EODMS images' \
                ' from a CSV file exported using eodms-order.py.')
        
        parser.add_argument('-u', '--username', help='The username of the ' \
                            'EODMS account used for authentication.')
        parser.add_argument('-p', '--password', help='The password of the ' \
                            'EODMS account used for authentication.')
        parser.add_argument('-i', '--input', help='The OrderInfo CSV file ' \
                            'exported from eodms-order.py script.')
        
        args = parser.parse_args()
        
        user = args.username
        password = args.password
        in_fn = args.input
            
        if user is None:
            user = input("Enter the username for authentication: ")
            if user == '':
                err_msg = "A username is required to order images."
                common.print_support(err_msg)
                sys.exit(1)
                
        if password is None:
            password = getpass.getpass(prompt='Enter the password for ' \
                        'authentication: ') 
            if password == '':
                err_msg = "A password is required to order images."
                common.print_support(err_msg)
                sys.exit(1)
                
        if in_fn is None or in_fn == '':
            in_fn = input("Enter the CSV file containing a list of images: ")
            if in_fn == '':
                err_msg = "A CSV file is required."
                common.print_support(err_msg)
                sys.exit(1)
                
        session = requests.Session()
        session.auth = (user, password)
        
        run(session, in_fn)
        
        print("\nProcess complete.")
        
        common.print_support()
        
    except Exception:
        trc_back = "\n%s" % traceback.format_exc()
        common.print_support(trc_back)
        
if __name__ == '__main__':
	sys.exit(main())