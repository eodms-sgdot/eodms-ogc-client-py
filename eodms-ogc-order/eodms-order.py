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
import requests
from xml.etree import ElementTree
import base64
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

MAX_ORDERS = 100

class Orderer:
    
    def __init__(self, session, record_id=None, in_fn=None, coll=None):
        """
        Initializer for Orderer.
        
        @type  session:   request.Session
        @param session:   A request session with authentication.
        @type  record_id: int
        @param record_id: The record ID for a single order.
        @type  in_fn:     str
        @param in_fn:     The file name of the exported CSV file from the 
                            EODMS search.
        @type  coll:      str
        @param coll:      The collection ID name (ex: RCMImageProducts).
        
        @rtype:  n/a
        @return: None
        """
        
        self.session = session
        self.record_id = record_id
        self.input_csv = in_fn
        self.coll_id = coll
        
        self.timeout = 120.0
        self.orders_header = ['Record ID', 'Order Key', 'Date', 'Collection ID', \
                                'Exception', 'Order ID', 'Order Item ID', 'Order ' \
                                'Status', 'Time Ordered']
                                
        self.collections = None
                                
    def set_collId(self, coll_id):
        '''
        Sets the collection ID name (coll_id)
        
        @type  coll_id: str
        @param coll_id: The collection ID name.
        
        @rtype:  n/a
        @return: None
        '''
        self.coll_id = coll_id
        
    def set_collIdByName(self, in_name, exact=True):
        '''
        Sets the collection ID name with the collection name
        
        @type  in_name: str
        @param in_name: The collection name.
        @type  exact:   boolean
        @param exact:   Determines whether the collection name should be 
                        compared exactly.
                        
        @rtype:  str
        @return: The collection ID name.
        '''
        
        # Get a dictionary of collections
        if self.collections is None:
            self.collections = self.get_collections()
        
        # Go through each collection to find the collection ID
        #   with the given name
        found_coll = []
        for coll_id, coll_name in self.collections.items():
            if exact:
                if coll_name == in_name:
                    found_coll.append(coll_id)
            else:
                if coll_name.find(in_name) > -1:
                    found_coll.append(coll_id)
        
        # If no collections could be found, return None
        if len(found_coll) == 0: return None
        
        # If more than one collection was found, return the list
        if len(found_coll) > 1: return found_coll
        
        # Set the coll_id to the only found collection
        self.coll_id = found_coll[0]
                    
        return self.coll_id
    
    def set_inputCSV(self, in_fn):
        '''
        Sets the input CSV filename.
        
        @type  in_fn: str
        @param in_fn: The input CSV filename.
        
        @rtype: n/a
        @return: None
        '''
        
        self.input_csv = in_fn
    
    def set_recordId(self, record_id):
        '''
        Sets the record ID for a single order.
        
        @type  record_id: int
        @param record_id: The record ID for a single order.
        
        @rtype: n/a
        @return: None
        '''
        
        self.record_id = record_id

    def add_orderInfo(self, in_recs, order_res):
        """
        Adds order information to a list of image records.
        
        @type  in_recs:   list
        @param in_recs:   A list of image records from a search result.
        @type  order_res: list
        @param order_res: A list of results from an order request.
        
        @rtype:  list
        @return: A list of image results with order information.
        
        """
        
        out_recs = []
        
        for rec in in_recs:
            
            # Get the order info for the current record
            order_info = None
            if order_res is not None:
                for o in order_res['items']:
                    if o['recordId'] == rec['Record ID']:
                        rec['Order ID'] = o['orderId']
                        rec['Order Item ID'] = o['itemId']
                        rec['Order Status'] = o['status']
                        cov_time = datetime.datetime.now()
                        rec['Time Ordered'] = cov_time.strftime(\
                                                "%Y%m%d_%H%M%S")
            else:
                rec['Exception'] = '"%s"' % str(order_res)
                
            out_recs.append(rec)
                
        return out_recs
        
    def determine_collection(self):
        '''
        Determines the collection of the images in the input
            CSV file.
        '''
        
        # If no input CSV file is set, return None
        if self.input_csv is None: return None
        
        # Import the CSV file
        recs = self.import_csv()
        
        frst_rec = recs[0]
        if 'Collection ID' in frst_rec.keys():
            # Get the Collection ID name
            self.coll_id = frst_rec['Collection ID']
            
            return self.coll_id
        elif 'Satellite' in frst_rec.keys():
            # Get the satellite name
            satellite = frst_rec['Satellite']
            
            # Get a dictionary of collections
            colls = self.get_collections()
            
            # Set the collection ID name
            self.coll_id = self.set_collIdByName(satellite, False)
            
            if isinstance(self.coll_id, list): return None
        
            return self.coll_id
        else:
            return None

    def get_collections(self, as_list=False):
        """
        Gets a list of available collections for the current user.
        
        @type  session: requests.Session
        @param session: The current session with authentication.
        @type  as_list: boolean
        @param as_list: Determines the type of return. If False, a dictionary
                            will be returned. If True, only a list of collection
                            IDs will be returned.
        
        @rtype:  dict or list (depending on value of as_list)
        @return: Either a dictionary of collections or a list of collection IDs 
                    depending on the value of as_list.
        """
        
        # List of collections that are either commercial products or not available 
        #   to the general public
        ignore_collections = ['163', 'RCMScienceData', 'Radarsat2RawProducts', 
                            'Radarsat1RawProducts', 'COSMO-SkyMed1', '162', 
                            '165', '164']
        
        # Create the query to get available collections for the current user
        query_url = "%s/wes/rapi/collections" % RAPI_DOMAIN
        
        # Send the query URL
        coll_res = common.send_query(query_url, self.session)
        
        # If a list is returned from the query, return it
        if isinstance(coll_res, list):
            return coll_res
        
        # Convert query to JSON
        coll_json = coll_res.json()
        
        # Create the collections dictionary
        self.collections = {}
        for coll in coll_json:
            for child in coll['children']:
                if child['collectionId'] in ignore_collections: continue
                for c in child['children']:
                    if c['collectionId'] in ignore_collections: continue
                    self.collections[c['collectionId']] = c['title']
        
        # If as_list is True, convert dictionary to list of collection IDs
        if as_list:
            collections = list(self.collections.values())
            return collections
        
        return self.collections
        
    def get_recordId(self, in_rec):
        """
        Get a record ID based on an image's collection. 
            Some results from the EODMS search result CSV file do not contain 
            a record ID so other fields are used to determine the record ID.
        
        @type  in_rec:  dict
        @param in_rec:  A dictionary of an image from the CSV file.
        @type  session: requests.Session
        @param session: The current session with authentication.
        @type  timeout: float
        @param timeout: The maximum timeout for the query request to the RAPI.
        
        @rtype  dict
        @return The record dictionary with the record ID.
        """
        
        # Get the collection ID for the image
        collection = in_rec['Collection ID']
        
        if collection == 'RCMImageProducts':
            # If the collection ID is RCMImageProducts:
            if 'Sequence ID' in in_rec.keys():
                # if the Sequence ID is in the image dictionary, 
                #   return it as the Record ID
                in_rec['Record ID'] = in_rec['Sequence ID']
                return in_rec
            elif 'Record ID' in in_rec.keys():
                # if the Record ID is in the image dictionary, return it
                return in_rec
            elif 'Downlink Segment ID' in in_rec.keys():
                # if the Downlink Segment ID is in the image dictionary,
                #   use it to query the RAPI
                downlink_seqId = in_rec['Downlink Segment ID']
                
                # Create the query with the downlink segment ID
                query = "RCM.DOWNLINK_SEGMENT_ID='%s'" % downlink_seqId
                query_enc = urllib.parse.quote(query)
                query_url = "%s/wes/rapi/search?collection=%s&query=%s" % \
                            (RAPI_DOMAIN, collection, query_enc)
                        
            print("\nQuery URL: %s" % query_url)
                
        elif collection == 'Radarsat2':
            if 'Sequence ID' in in_rec.keys():
                # If the Sequence ID is in the image dictionary, 
                #   return it as the Record ID
                in_rec['Record ID'] = in_rec['Sequence ID']
                return in_rec
            elif 'Record ID' in in_rec.keys():
                # If the Record ID is in the image dictionary, return it
                return in_rec
            if 'Image Id' in in_rec.keys():
                # If the Image ID is in the image dictionary,
                #   use it to query the RAPI
                query = "RSAT2.IMAGE_ID='%s'" % in_rec['Image Id']
                query_enc = urllib.parse.quote(query)
                query_url = "%s/wes/rapi/search?collection=%s&query=%s" % \
                            (RAPI_DOMAIN, collection, query_enc)
                            
        elif collection == 'Radarsat1':
            if 'Sequence ID' in in_rec.keys():
                # If the Sequence ID is in the image dictionary, 
                #   return it as the Record ID
                in_rec['Record ID'] = in_rec['Sequence ID']
                return in_rec
            elif 'Record ID' in in_rec.keys():
                # If the Record ID is in the image dictionary, return it
                return in_rec
            if 'Order Key' in in_rec.keys():
                # If the Order Key is in the image dictionary,
                #   use it to query the RAPI
                order_key = in_rec['Order Key']
                query = "ARCHIVE_IMAGE.ORDER_KEY='%s'" % order_key
                query_enc = urllib.parse.quote(query)
                query_url = "%s/wes/rapi/search?collection=%s&query=%s" % \
                            (RAPI_DOMAIN, collection, query_enc)
                            
        else:
            if 'Sequence ID' in in_rec.keys():
                # If the Sequence ID is in the image dictionary, 
                #   return it as the Record ID
                in_rec['Record ID'] = in_rec['Sequence ID']
                return in_rec
            elif 'Record ID' in in_rec.keys():
                # If the Record ID is in the image dictionary, return it
                return in_rec
            if 'Order Key' in in_rec.keys():
                # If the Order Key is in the image dictionary,
                #   use it to query the RAPI
                order_key = in_rec['Order Key']
                query = "ARCHIVE_IMAGE.ORDER_KEY='%s'" % order_key
                query_enc = urllib.parse.quote(query)
                query_url = "%s/wes/rapi/search?collection=%s&query=%s" % \
                            (RAPI_DOMAIN, collection, query_enc)
        
        # Send the query to the RAPI
        res = common.send_query(query_url, self.session, 120.0, quiet=False)
        
        # If the results is a list, an error occurred
        if isinstance(res, list):
            print("WARNING: %s" % ' '.join(res))
            return res
        
        # Convert RAPI results to JSON
        res_json = res.json()
        
        # Get the results from the JSON
        results = res_json['results']
        
        # If no results, return as error
        if len(results) == 0:
            err = "No images could be found."
            print("\nWARNING: %s" % err)
            print("Skipping this entry")
            return [err]
        
        # Use the results from the query to get the Record ID
        if collection == 'RCMImageProducts':
            for res in results:
                # Go through each record in the results to locate the
                #   specific record with the order key
                order_key = in_rec['Order Key']
                if res['title'] == order_key:
                    mdata = res['metadata2']
                    
                    # Create the output record dictionary and fill it
                    #   with the record's metadata and the record ID
                    in_rec['Record ID'] = res['recordId']
                    # in_rec['Order Key'] = res['title']
                    
                    for m in mdata:
                        if m['id'] == 'CATALOG_IMAGE.START_DATETIME':
                            in_rec['Date'] = m['value']
        elif collection == 'Radarsat2':
            for res in results:
                mdata = res['metadata2']
                
                for m in mdata:
                    # Go through each results and locate the Image ID to
                    #   get the Record ID of the image
                    if m['id'] == 'RSAT2.IMAGE_ID':
                        if in_rec['Image Id'] == m['value']:
                            in_rec['Record ID'] = res['recordId']
        
        elif collection == 'Radarsat1':
            if len(results) == 1:
                # Get the Record ID from the one result
                in_rec['Record ID'] = results[0]['recordId']
            
        return in_rec
        
    def import_csv(self):
        '''
        Imports the rows from the CSV file into a dictionary of 
            records.
        '''
        
        # Open the input file
        in_f = open(self.input_csv, 'r')
        in_lines = common.get_lines(in_f)
        
        # Get the header from the first row
        in_header = in_lines[0].replace('\n', '').split(',')
        
        # Check for columns in input file
        if 'Sequence ID' not in in_header and \
            'Order Key' not in in_header and \
            'Downlink Segment ID' not in in_header and \
            'Image Id' not in in_header and \
            'Record ID' not in in_header:
            err_msg = '''The input file does not contain the proper columns.
  The input file must contain one of the following columns:
    Record ID
    Sequence ID
    Image ID
    Order Key
    A combination of Downlink Segment ID and Order Key'''
            common.print_support(err_msg)
            sys.exit(1)
        
        # Populate the list of records from the input file
        records = []
        for l in in_lines[1:]:
            rec = {}
            l_split = l.replace('\n', '').split(',')
            
            if len(l_split) < len(in_header):
                continue
            
            for idx, h in enumerate(in_header):
                rec[h] = l_split[idx]
            
            if self.coll_id is not None:
                
                rec['Collection ID'] = self.coll_id
            
                # Get the record ID using the information from the CSV entry
                rec = self.get_recordId(rec)
            
            # Add the record to the list of records
            records.append(rec)
        
        # Close the input file
        in_f.close()
        
        return records
        
    def log_orders(self, in_recs, orders_csv, error=False):
        """
        Saves the order results to the CSV file
        
        @type  in_recs:       list
        @param in_recs:       The list of images from the original CSV file.
        @type  orders_csv:    file
        @param orders_csv:    The output CSV file object.
        @type  error:         boolean
        @param error:         Determines whether the input orders_res is an error.
        
        @rtype:  None
        @return: None
        """
        
        for rec in in_recs:
        
            # Write record to CSV
            del_lst = []
            for k in rec.keys():
                if k not in self.orders_header:
                    del_lst.append(k)
                    
            for k in del_lst:
                del rec[k]
            
            # Write the values to the output CSV file
            out_vals = []
            for h in self.orders_header:
                if h in rec.keys():
                    out_vals.append(rec[h])
                else:
                    out_vals.append('')
            orders_csv.write('%s\n' % ','.join(out_vals))
        
    def send_orders(self, in_res):
        """
        Sends a POST request to the RAPI in order to order images.
        
        @type  in_res:   list
        @param in_res:   A list of records.
        @type  user:     str
        @param user:     The username of the authentication.
        @type  password: str
        @param password: The password of the authentication.
        @type  timeout:  float
        @param timeout:  The timeout in seconds for the request.
        @type  session:  requests.Session
        @param session:  A previously created session with authentication.
        
        @rtype:          json
        @return:         The order information from the order request.
        """
        
        try:
            # if self.session is None:
                # # If no session provided, create one with the provided username
                # #username, password = get_auth(user)
            
                # # Create a session with the authentication
                # self.session = requests.Session()
                # self.session.auth = (user, password)
            
            # Add the 'Content-Type' option to the header
            self.session.headers.update({'Content-Type': 'application/json'})
            
            #print("in_res: %s" % in_res)
            
            # Create the items list for the POST request JSON
            items = []
            for r in in_res:
                if not isinstance(r, dict): continue
                
                if 'Exception' in r.keys(): continue
                
                item = {"collectionId": r['Collection ID'], 
                        "recordId": r['Record ID']}
                items.append(item)
            
            # If there are no items, return None
            if len(items) == 0: return None
            
            # Create the dictionary for the POST request JSON
            post_dict = {"destinations": [], 
                        "items": items}
            
            # Dump the dictionary into a JSON object
            post_json = json.dumps(post_dict)
            
            # Set the RAPI URL
            order_url = "%s/wes/rapi/order" % RAPI_DOMAIN
            
            # Send the JSON request to the RAPI
            try:
                order_res = self.session.post(url=order_url, data=post_json)
                order_res.raise_for_status()
            except requests.exceptions.HTTPError as errh:
                return "Http Error: %s" % errh
            except requests.exceptions.ConnectionError as errc:
                return "Error Connecting: %s" % errc
            except requests.exceptions.Timeout as errt:
                return "Timeout Error: %s" % errt
            except requests.exceptions.RequestException as err:
                return "Exception: %s" % err
            
            if not order_res.ok:
                err = common.get_exception(order_res)
                if isinstance(err, list):
                    return '; '.join(err)
            
            return order_res.json()
        except Exception as err:
            traceback.print_exc(file=sys.stdout)
            return err
 
    def run(self):
        """
        Runs the entire process for ordering images from the EODMS.
        
        @rtype:          None
        @return:         None
        """
        
        # Get current timestamp for the output CSV filename
        fn_time = datetime.datetime.now()
        fn_str = fn_time.strftime("%Y%m%d_%H%M%S")
        
        print("\nProcess started at: %s" % fn_str)
        
        # Get image information from the input file
        cur_recs = self.import_csv()
        
        # Create the file for the records
        orders_fn = '%s_OrderInfo.csv' % fn_str
        orders_csv = open(orders_fn, 'w')
        
        orders_csv.write('%s\n' % ','.join(self.orders_header))
        
        order_count = 0
        order_res = None
        if not isinstance(cur_recs, list):
            # If the cur_recs is not a list, an error occurred.
            err_msg = cur_recs.text
            common.print_support(err_msg)
            sys.exit(1)
        else:
        
            print("\nTotal records to order: %s" % len(cur_recs))
        
            order_ids = []
            # The EODMS restricts users to 100 images per order.
                #   If there are more than 100 images to order,
                #   the script divides them into separate orders.
            for i in range(0, len(cur_recs), MAX_ORDERS):
                
                end_i = i + MAX_ORDERS
                
                if end_i > len(cur_recs): end_i = len(cur_recs)
                
                print("\nSending order for records %s to %s..." % (i + 1, end_i))
                
                # Get the next 100 images
                if len(cur_recs) < i + MAX_ORDERS:
                    sub_recs = cur_recs[i:]
                else:
                    sub_recs = cur_recs[i:MAX_ORDERS + i]
                
                # Send the order requests to the RAPI
                order_res = self.send_orders(sub_recs) #, session, timeout)
                
                if order_res is None:
                    print("\nNo images could be ordered.")
                    continue
                    
                print("\nNumber of orders: %s" % len(order_res['items']))
                
                # Add order results to the records
                sub_recs = self.add_orderInfo(sub_recs, order_res)
                
                # If the order results is not a dictionary, report as an error.
                if not isinstance(order_res, dict):
                    print("\nWARNING: An error occurred while sending the order:")
                    #print(order_res)
                    self.log_orders(sub_recs, orders_csv, \
                                True)
                    continue
                
                # Verify that each image order item was sent successfully
                for r in sub_recs:
                    if 'Order ID' not in r.keys():
                        print("Order for image with Record ID '%s' did not " \
                                "send." % r['Record ID'])
                
                # Add order ID to a list of order IDs
                order_ids.append(str(order_res['items'][0]['orderId']))
                
                # Send info to the output CSV file
                self.log_orders(sub_recs, orders_csv)
                
                # Track the number of successful orders
                order_count += len(order_res['items'])
                
        # Get the end time for the entire process
        end_time = datetime.datetime.now()
        end_str = end_time.strftime("%Y%m%d_%H%M%S")
        
        # Add the end time to the output CSV
        orders_csv.write('\n')
        orders_csv.write('Order process started at: %s\n' % fn_str)
        orders_csv.write("Order process ended at: %s\n" % end_str)
        orders_csv.close()
        
        print("\nProcess started at: %s" % fn_str)
        print("Process ended at: %s" % end_str)
        
        print("\n%s images were ordered with the following Order ID(s):" % \
                order_count)
        print("  %s" % '\n  '.join(order_ids))
        
        if order_count > 0:
            print("\nYou will receive emails with the download links to these " \
                    "orders.")
        
        print("\nA list of results can be found in the CSV file '%s'." \
                % orders_fn)
        
    def run_single(self):
        """
        Orders a single image from the WCS.
        
        @type  user:     str
        @param user:     The username for authentication.
        @type  password: str
        @param password: The password for authentication.
        @type  image_id: str
        @param image_id: The ID of the image.
        
        @rtype:          None
        @return:         None
        """
        
        # Get current timestamp for the output CSV filename
        fn_time = datetime.datetime.now()
        fn_str = fn_time.strftime("%Y%m%d_%H%M%S")
        
        print("\nProcess started at: %s" % fn_str)
        
        # Create a session with the authentication
        # session = requests.Session()
        # session.auth = (user, password)
        
        # Create the file for the records
        orders_fn = '%s_OrderInfo.csv' % fn_str
        orders_csv = open(orders_fn, 'w')
        orders_header = ['Record ID', 'Order Key', 'Date', 'Collection ID', \
                        'Exception', 'Order ID', 'Order Item ID', 'Order ' \
                        'Status', 'Time Ordered']
        orders_csv.write('%s\n' % ','.join(orders_header))
        
        order_count = 0
        order_res = None
        
        # Get a dictionary of collections
        collections = self.get_collections()
        
        rec = {}
        rec['Record ID'] = self.record_id
        
        # Set the collection ID
        rec['Collection ID'] = self.coll_id
        
        recs = [rec]
                
        # Send the order requests to the RAPI
        order_res = self.send_orders(recs)
        
        order_id = order_res['items'][0]['orderId']
        
        recs = self.add_orderInfo(recs, order_res)
        
        self.log_orders(recs, orders_csv)
            
        order_count += len(order_res['items'])
                
        # Get the end time for the entire process
        end_time = datetime.datetime.now()
        end_str = end_time.strftime("%Y%m%d_%H%M%S")
        
        # Add the end time to the output CSV
        orders_csv.write('\n')
        orders_csv.write('Order process started at: %s\n' % fn_str)
        orders_csv.write("Order process ended at: %s\n" % end_str)
        orders_csv.close()
        
        print("\nProcess started at: %s" % fn_str)
        print("Process ended at: %s" % end_str)
            
        print("\n%s images were ordered with the following Order ID(s):" % \
                order_count)
        print("  %s" % order_id)
        
        print("\nYou will receive emails with the download links to these orders.")
        
        print("\nA list of results can be found in the CSV file '%s'." \
                % orders_fn)

def main():
    
    try:
        parser = argparse.ArgumentParser(description='Order EODMS products.')
        
        parser.add_argument('-u', '--username', help='The username of the ' \
                            'EODMS account used for authentication.')
        parser.add_argument('-p', '--password', help='The password of the ' \
                            'EODMS account used for authentication.')
        parser.add_argument('-r', '--recordid', help='The record ID for a ' \
                            'single image. If this parameter is entered, ' \
                            'only the image with this ID will be ordered.')
        parser.add_argument('-i', '--input', help='A CSV file containing a ' \
                            'list of record IDs. The process will only ' \
                            'order the images from this file.\nThe file ' \
                            'should contain a column called "Record ID", ' \
                            '"Sequence ID" or "Downlink Segment ID" with ' \
                            'an "Order Key" column.')
        parser.add_argument('-c', '--collection', help='The collection of ' \
                            'the images being ordered.')
        
        args = parser.parse_args()
        
        user = args.username
        password = args.password
        recordid = args.recordid
        in_fn = args.input
        coll = args.collection
            
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
        
        if recordid is None:
            if in_fn is None or in_fn == '':
                in_fn = input("Enter the CSV file containing a list of " \
                                "images or an image's Record ID: ")
                if in_fn == '':
                    err_msg = "A CSV file is required."
                    common.print_support(err_msg)
                    sys.exit(1)
                    
                if in_fn.isdigit():
                    recordid = in_fn
                    in_fn = None
                
        session = requests.Session()
        session.auth = (user, password)
        
        order = Orderer(session)
                
        if coll is None:
            
            # Determine the collection from the first record
            #print("\nGetting a list of collections...")
            if in_fn is not None:
                order.set_inputCSV(in_fn)
                coll = order.determine_collection()
            
            # If no collection can be determined, ask the user
            if coll is None:
                if in_fn is not None:
                    print("\nCannot determine collection using the CSV file.")
                colls = order.get_collections(True)
                collections = '\n'.join(['%s. %s' % (i + 1, c) for i, c in \
                                enumerate(colls)])
                print("\nList of collections:\n%s" % collections)
                coll_idx = input("Enter the collection number from the list above: ")
                if coll_idx == '':
                    err_msg = "A collection is required to order images."
                    common.print_support(err_msg)
                    sys.exit(1)
                    
                coll = colls[int(coll_idx) - 1]
        
        order.set_collIdByName(coll)
        
        if recordid is not None:
            order.set_recordId(recordid)
            order.run_single()
        else:
            order.set_inputCSV(in_fn)
            order.run()
            
        print("\nProcess complete.")
        
        common.print_support()
        
    except Exception:
        trc_back = "\n%s" % traceback.format_exc()
        common.print_support(trc_back)

if __name__ == '__main__':
	sys.exit(main())
