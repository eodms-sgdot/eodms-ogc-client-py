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

import os
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

def get_lines(in_f):
    # Check if the input file is bytes
    try:
        in_lines = in_f.readlines()
        
        return in_lines
    except Exception:
        err_msg = "The input file cannot be read."
        print_support(err_msg)
        sys.exit(1)

def get_exception(res, output='str'):
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
    
    in_str = res.text

    # If the input XML is None, return None
    if in_str is None: return None
    
    if is_json(in_str): return None
    
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

def is_json(my_json):
    """
    Checks to see in the input item is in JSON format.
    
    @type  my_json: str
    @param my_json: A string value from the requests results.
    """
    try:
        json_object = json.loads(my_json)
    except (ValueError, TypeError) as e:
        #print("e: %s" % e)
        return False
    return True
    
def print_support(err_str=None):
    
    if err_str is None:
        print("\nIf you have any questions or require support, " \
                "please contact the EODMS Support Team at " \
                "nrcan.eodms-sgdot.rncan@canada.ca")
    else:
        print("\nERROR: %s" % err_str)
        
        print("\nExiting process.")
        
        print("\nFor help, please contact the EODMS Support Team at " \
                "nrcan.eodms-sgdot.rncan@canada.ca")
    

def send_query(query_url, session=None, timeout=60.0, attempts=4, 
                record_name=None, quiet=True):
    """
    Send a query to the RAPI.
    
    @type  query_url:   str
    @param query_url:   The query URL.
    @type  session:     requests.Session
    @param session:     The current session with authentication.
    @type  timeout:     float
    @param timeout:     The length of the timeout in seconds.
    @type  attempts:    int
    @param attempts:    The maximum number of attempts for query the RAPI.
    @type  record_name: str
    @param record_name: A string used to supply information for the record 
                        in a print statement.
    
    @rtype  request.Response
    @return The response returned from the RAPI.
    """
    
    verify = True
    if query_url.find('www-pre-prod') > -1:
        verify = False
    
    if not quiet:
        print("\nRAPI Query URL: %s" % query_url)
    
    res = None
    attempt = 1
    err = None
    # Get the entry records from the RAPI using the downlink segment ID
    while res is None and attempt <= attempts:
        # Continue to attempt if timeout occurs
        try:
            if record_name is None:
                if not quiet:
                    print("\nQuerying the RAPI (attempt %s)" % attempt)
            else:
                if not quiet:
                    print("\nQuerying the RAPI for '%s' (attempt %s)" % \
                            (record_name, attempt))
            if session is None:
                res = requests.get(query_url, timeout=timeout, verify=verify)
            else:
                res = session.get(query_url, timeout=timeout, verify=verify)
            res.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            print("HTTP Error: %s" % errh)
            attempt += 1
            if attempt == attempts:
                err = "HTTP Error: %s" % errh
        except requests.exceptions.ConnectionError as errc:
            print("Error Connecting: %s" % errc)
            attempt += 1
            if attempt == attempts:
                err = "Error Connecting: %s" % errc
        except requests.exceptions.Timeout as errt:
            print("Timeout Error: %s" % errt)
            attempt += 1
            if attempt == attempts:
                err = "Timeout Error: %s" % errt
        except requests.exceptions.RequestException as err:
            print("Exception: %s" % err)
            attempt += 1
            if attempt == attempts:
                err = "Exception: %s" % err
        except:
            print("Unexpected error: %s" % sys.exc_info()[0])
            attempt += 1
            if attempt == attempts:
                err = "Unexpected error: %s" % sys.exc_info()[0]
            
    if err is not None:
        return [err]
            
    # If no results from RAPI, return None
    if res is None: return None
    
    # Check for exceptions that weren't already caught
    err = get_exception(res)
    
    if isinstance(err, list):
        if '401 - Unauthorized' in err:
            print("\nERROR: An authentication error has occurred while trying to access the EODMS RAPI. Please run this script again with your username and password.")
            print_support()
            sys.exit(1)
            
        print("WARNING: %s" % ' '.join(err))
        return err
        
    return res