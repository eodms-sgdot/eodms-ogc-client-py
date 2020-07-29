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

def get_exception(in_str, output='str'):
    """
    Gets the Exception text (or XML) from an request result.
    
    @type  in_xml: xml.etree.ElementTree.Element
    @param in_xml: The XML which will be checked for an exception.
    @type  output: str
    @param output: Determines what type of output should be returned 
                    (default='str').
                   Options:
                   - 'str': returns the XML Exception as a string
                   - 'tree': returns the XML Exception as a 
                                xml.etree.ElementTree.Element
                                
    @rtype:        str or xml.etree.ElementTree.Element
    @return:       The Exception XML text or element depending on 
                    the output variable.
    """

    # If the input XML is None, return None
    if in_str is None: return None
    
    if is_json(in_str): return in_str
    
    # If the input is a string, convert it to a xml.etree.ElementTree.Element
    if isinstance(in_str, str):
        root = ElementTree.fromstring(in_str)
    else:
        root = in_str
    
    # Cycle through the input XML and location the ExceptionText element
    out_except = []
    for child in root.iter('*'):
        if child.tag.find('ExceptionText') > -1:
            if output == 'tree':
                return child
            else:
                return child.text
        elif child.tag.find('p') > -1:
            out_except.append(child.text)
            
    return out_except
                
def get_fromOrderKey(in_rec, session, timeout=60.0, attempts=4):
    """
    Gets the record information from the RAPI using the order key.
    
    @type  in_rec:     str
    @param in_rec:     A record from the saved CSV search results from the EODMS.
    @type  timeout:    float
    @param timeout:    The timeout in seconds for the request.
    @type  attempts:   int
    @param attempts:   The number of attempts if a timeout occurs when accessing the RAPI.
    
    @rtype:     dict
    @return:    A dictionary with information regarding the record found in the RAPI.
    """
    
    # Get the "Order Key" and "Downlink Segment ID" from the CSV file record
    order_key = in_rec['Order Key']
    download_segment_id = in_rec['Downlink Segment ID']
    
    # Create the query with the downlink segment ID
    query = "RCM.DOWNLINK_SEGMENT_ID='%s'" % download_segment_id
    query_enc = urllib.parse.quote(query)
    query_url = "https://www.eodms-sgdot.nrcan-rncan.gc.ca/wes/rapi/search" \
                "?collection=RCMImageProducts&query=%s" % query_enc
                
    print("\nQuery URL: %s" % query_url)
    
    res = None
    attempt = 1
    # Get the entry records from the RAPI using the downlink segment ID
    while res is None and attempt <= attempts:
        # Continue to attempt if timeout occurs
        try:
            print("\nGetting record for '%s' (attempt %s)" % \
                    (order_key, attempt))
            res = session.get(query_url, timeout=timeout)
        except:
            attempt += 1
    
    # If no results from RAPI, return None
    if res is None: return None
    
    err = get_exception(res.text)
    
    if isinstance(err, list):
        print("WARNING: %s" % ' '.join(err))
        return err
    
    # Convert RAPI results to JSON
    res_json = res.json()
    
    # Get the results from the JSON
    results = res_json['results']
    
    print("\nNumber of results: %s" % len(results))
    
    if len(results) == 0:
        err = "No images could be found containing Downlink " \
                "Segment ID: %s" % download_segment_id
        print("\nWARNING: No images could be found containing Downlink " \
                "Segment ID: %s" % download_segment_id)
        print("Skipping this entry")
        #answer = input("Press enter...")
        return [err]
    
    for res in results:
        # Go through each record in the results to locate the
        #   specific record with the order key
        if res['title'] == order_key:
            mdata = res['metadata2']
            
            # Create the output record dictionary and fill it
            #   with the record's metadata and the record ID
            rec = {}
            rec['Record ID'] = res['recordId']
            rec['Collection ID'] = res['collectionId']
            rec['Order Key'] = res['title']
            
            for m in mdata:
                if m['id'] == 'CATALOG_IMAGE.START_DATETIME':
                    rec['Date'] = m['value']
    
    return rec
    
def is_json(my_json):
    """
    Checks to see in the input item is in JSON format.
    
    @type  my_json: str
    @param my_json: A string value from the requests results.
    """
    try:
        json_object = json.loads(my_json)
    except (ValueError, TypeError) as e:
        print("e: %s" % e)
        return False
    return True
    
def log_orders(in_recs, order_res, orders_csv, orders_header, error=False):
    """
    Saves the order results to the CSV file
    
    @type  in_recs:       list
    @param in_recs:       The list of images from the original CSV file.
    @type  order_res:     JSON
    @param order_res:     A JSON containing the results from the order request.
    @type  orders_csv:    file
    @param orders_csv:    The output CSV file object.
    @type  orders_header: list
    @param orders_header: A list of the column names for the output CSV.
    @type  error:         boolean
    @param error:         Determines whether the input orders_res is an error.
    
    @rtype:  None
    @return: None
    """
    
    if 'Record ID' in orders_header:
        id_col = 'Record ID'
    else:
        id_col = 'Sequence ID'
    
    for rec in in_recs:
        
        # Get the order info for the current record
        order_info = None
        if order_res is not None and not error:
            for o in order_res['items']:
                if o['recordId'] == rec[id_col]:
                    rec['Order ID'] = o['orderId']
                    rec['Order Item ID'] = o['itemId']
                    rec['Order Status'] = o['status']
                    cov_time = datetime.datetime.now()
                    rec['Time Ordered'] = cov_time.strftime(\
                                            "%Y%m%d_%H%M%S")
        else:
            rec['Exception'] = '"%s"' % str(order_res)
    
        # Write record to CSV
        del_lst = []
        for k in rec.keys():
            if k not in orders_header:
                del_lst.append(k)
                
        for k in del_lst:
            del rec[k]
        
        # Write the values to the output CSV file
        out_vals = []
        for h in orders_header:
            if h in rec.keys():
                out_vals.append(rec[h])
            else:
                out_vals.append('')
        orders_csv.write('%s\n' % ','.join(out_vals))
    
def send_orders(in_res, session=None, user=None, password=None):
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
        if session is None:
            # If no session provided, create one with the provided username
            #username, password = get_auth(user)
        
            # Create a session with the authentication
            session = requests.Session()
            session.auth = (user, password)
        
        # Add the 'Content-Type' option to the header
        session.headers.update({'Content-Type': 'application/json'})
        
        # Create the items list for the POST request JSON
        items = []
        for r in in_res:
            if 'Exception' in r.keys(): continue
            if 'Record ID' in r.keys():
                id_col = 'Record ID'
            else:
                id_col = 'Sequence ID'
            item = {"collectionId": r['Collection ID'], 
                    "recordId": r[id_col]}
            items.append(item)
        
        # If there are no items, return None
        if len(items) == 0: return None
        
        # Create the dictionary for the POST request JSON
        post_dict = {"destinations": [], 
                    "items": items}
        
        # Dump the dictionary into a JSON object
        post_json = json.dumps(post_dict)
        
        # Set the RAPI URL
        order_url = "https://www.eodms-sgdot.nrcan-rncan.gc.ca/wes/rapi/order"
        
        # Send the JSON request to the RAPI
        order_res = session.post(url=order_url, data=post_json)
                                    
        #print("order_res: %s" % order_res)
        
        return order_res.json()
    except Exception as err:
        traceback.print_exc(file=sys.stdout)
        return err
 
def run(user, password, in_fn):
    """
    Runs the entire process for ordering images from the RCM.
    
    @type  user:     str
    @param user:     The username for authentication.
    @type  password: str
    @param password: The password for authentication.
    @type  in_fn:    str
    @param in_fn:    An optional CSV file containing a list of 
                        record IDs.
                     The file should contain the following header and 
                     columns:
                        id,title,date,collection_id
    @type  bbox (not used):     str
    @param bbox (not used):     The bounding box used for the query request.
    @type  maximum (not used):  int or str
    @param maximum (not used):  The maximum number of records to be ordered.
    @type  start (not used):    str
    @param start (not used):    The maximum number of records to be ordered.
    @type  end (not used):      str
    @param end (not used):      The maximum number of records to be ordered.
    
    @rtype:          None
    @return:         None
    """
    
    # Set defaults
    gap = 10.0
    timeout = 120.0
    
    # Set variables to 0
    passes = 0
    fails = 0
    rec_count = 0
    
    # Get current timestamp for the output CSV filename
    fn_time = datetime.datetime.now()
    fn_str = fn_time.strftime("%Y%m%d_%H%M%S")
    
    print("\nProcess started at: %s" % fn_str)
    
    # Create a session with the authentication
    session = requests.Session()
    session.auth = (user, password)
    
    id_col = 'Record ID'
    
    # Get image information from the input file
    
    # Open the input file
    in_f = open(in_fn, 'r')
    in_lines = in_f.readlines()
    
    # Get the header from the first row
    in_header = in_lines[0].replace('\n', '').split(',')
    
    # Populate the list of records from the input file
    cur_recs = []
    rapi_count = 0
    for l in in_lines[1:]:
        rec = {}
        l_split = l.replace('\n', '').split(',')
        for idx, h in enumerate(in_header):
            rec[h] = l_split[idx]
            
        rec['Collection ID'] = "RCMImageProducts"
            
        if 'Sequence ID' in rec.keys():
            # If sequence_id was provided
            #rec['Sequence ID'] = rec['sequence_id']
            id_col = 'Sequence ID'
        elif 'Downlink Segment ID' in rec.keys():
            # Determine the record ID using the order key and 
            #   downlink segment ID.
            # The record ID will be used to order the image
            #   in the next step
            res = get_fromOrderKey(rec, session, timeout)
            if res is None:
                # If no results found using the order key
                rec['Record ID'] = 'N/A'
                rec['Exception'] = 'The RAPI search request timed out.'
            elif isinstance(res, list):
                rec['Record ID'] = 'N/A'
                rec['Exception'] = ' '.join(res)
            else:
                rapi_count += 1
                rec = res
        
        # Add the record to the list of records
        cur_recs.append(rec)
    
    # Close the input file
    in_f.close()
    
    # Create the file for the records
    orders_fn = '%s_OrderInfo.csv' % fn_str
    orders_csv = open(orders_fn, 'w')
    orders_header = [id_col, 'Order Key', 'Date', 'Collection ID', 'Exception', \
                    'Order ID', 'Order Item ID', 'Order Status', \
                    'Time Ordered']
    orders_csv.write('Order process started at: %s\n' % fn_str)
    orders_csv.write('%s\n' % ','.join(orders_header))
    
    if rapi_count > 0:
        print("\n%s records returned after querying the RAPI." % rapi_count)
    
    order_count = 0
    order_res = None
    if not isinstance(cur_recs, list):
        # If the cur_recs is not a list, an error occurred.
        err_msg = cur_recs.text
        print("\nERROR: %s" % err_msg)
        if err_msg.find('Authorization required') > -1:
            print("Exiting process.")
            sys.exit(1)
    else:
    
        print("\nTotal records to order: %s" % len(cur_recs))
    
        order_ids = []
        for i in range(0, len(cur_recs), 100):
            
            end_i = i + 100
            
            if end_i > len(cur_recs): end_i = len(cur_recs)
            
            print("\nSending order for records %s to %s..." % (i + 1, end_i))
            
            if len(cur_recs) < i + 100:
                sub_recs = cur_recs[i:]
            else:
                sub_recs = cur_recs[i:100 + i]
            
            # Send the order requests to the RAPI
            order_res = send_orders(sub_recs, session, timeout)
            
            #print("order_res: %s" % type(order_res))
            
            if not isinstance(order_res, dict):
                print("WARNING: An error occurred while sending the order:")
                print(order_res)
                log_orders(sub_recs, order_res, orders_csv, orders_header, \
                            True)
                continue
            
            #print("order_res: %s" % order_res)
            order_ids.append(order_res['items'][0]['orderId'])
            
            #print("sub_recs: %s" % sub_recs)
            log_orders(sub_recs, order_res, orders_csv, orders_header)
                
            print("Order sent successfully; Order ID: %s" % sub_recs[0]['Order ID'])
                
            order_count += len(order_res['items'])
            
    # Get the end time for the entire process
    end_time = datetime.datetime.now()
    end_str = end_time.strftime("%Y%m%d_%H%M%S")
    
    # Add the end time to the output CSV
    orders_csv.write("Order process ended at: %s\n" % end_str)
    orders_csv.close()
    
    print("\nProcess started at: %s" % fn_str)
    print("Process ended at: %s" % end_str)
        
    print("\n%s images were ordered with the following Order ID(s):" % \
            order_count)
    print("  %s" % '\n  '.join(order_ids))
    
    print("\nYou will receive emails with the download links to these orders.")
    
    print("\nA list of results can be found in the CSV file '%s'." \
            % orders_fn)
    
def run_single(user, password, image_id):
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
    session = requests.Session()
    session.auth = (user, password)
    
    # Create the file for the records
    orders_fn = '%s_OrderInfo.csv' % fn_str
    orders_csv = open(orders_fn, 'w')
    orders_header = ['Record ID', 'Order Key', 'Date', 'Collection ID', 'Exception', \
                    'Order ID', 'Order Item ID', 'Order Status', \
                    'Time Ordered']
    orders_csv.write('Order process started at: %s\n' % fn_str)
    orders_csv.write('%s\n' % ','.join(orders_header))
    
    order_count = 0
    order_res = None
    
    rec = {}
    rec['Record ID'] = image_id
    rec['Collection ID'] = 'RCMImageProducts'
    
    recs = [rec]
            
    # Send the order requests to the RAPI
    order_res = send_orders(recs, session)
            
    #print("order_res: %s" % order_res)
    #order_ids.append(order_res['items'][0]['orderId'])
    order_id = order_res['items'][0]['orderId']
    
    log_orders(recs, order_res, orders_csv, orders_header)
        
    order_count += len(order_res['items'])
            
    # Get the end time for the entire process
    end_time = datetime.datetime.now()
    end_str = end_time.strftime("%Y%m%d_%H%M%S")
    
    # Add the end time to the output CSV
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

    parser = argparse.ArgumentParser(description='Order RCM products.')
    
    parser.add_argument('-u', '--username', help='The username of the ' \
                        'EODMS account used for authentication.')
    parser.add_argument('-p', '--password', help='The password of the ' \
                        'EODMS account used for authentication.')
    parser.add_argument('-i', '--id', help='The record ID for a single ' \
                        'image. If this parameter is entered, only the ' \
                        'image with this ID will be ordered.')
    parser.add_argument('-f', '--input', help='A CSV file containing a list ' \
                        'of record IDs. The process will only order the ' \
                        'images from this file.\nThe file should contain a ' \
                        'column called "Record ID", "Sequence ID" or "Downlink ' \
                        'Segment ID" with an "Order Key" column.')
    
    args = parser.parse_args()
    
    user = args.username
    password = args.password
    id = args.id
    in_fn = args.input
    
    if id is not None:
        if user is None:
            user = input("Enter the username for authentication: ")
            if user == '':
                print("\nERROR: A username is required to order images.")
                print("Exiting process.")
                sys.exit(1)
                
        if password is None:
            password = getpass.getpass(prompt='Enter the password for ' \
                        'authentication: ') 
            if password == '':
                print("\nERROR: A password is required to order images.")
                print("Exiting process.")
                sys.exit(1)
    
        run_single(user, password, id)
        sys.exit(0)
        
    if user is None:
        user = input("Enter the username for authentication: ")
        if user == '':
            print("\nERROR: A username is required to order images.")
            print("Exiting process.")
            sys.exit(1)
            
    if password is None:
        password = getpass.getpass(prompt='Enter the password for ' \
                    'authentication: ') 
        if password == '':
            print("\nERROR: A password is required to order images.")
            print("Exiting process.")
            sys.exit(1)
            
    if in_fn is None or in_fn == '':
        in_fn = input("Enter the CSV file containing a list of images: ")
        if in_fn == '':
            print("\nERROR: A CSV file is required.")
            print("Exiting process.")
            sys.exit(1)
    
    run(user, password, in_fn)

if __name__ == '__main__':
	sys.exit(main())