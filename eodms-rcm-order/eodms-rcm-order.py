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

def build_record(rec_element):
    """
    Extracts information from an XML tree for a record dictionary.
    
    @type  rec_element: xml.etree.ElementTree.Element
    @param rec_element: The slope of the line.
    
    @rtype:             dictionary
    @return:            The input XML parsed into a dictionary.
    """
    
    # Set the namespaces
    dc_nspace = '{http://purl.org/dc/elements/1.1/}'
    dct_nspace = '{http://purl.org/dc/terms/}'
    csw_nspace = '{http://www.opengis.net/cat/csw/2.0.2}'

    rec_dict = {}
    
    # Set the image ID
    id_str = get_tag(rec_element, dc_nspace, 'identifier')
    rec_dict['id'] = id_str
    
    # Set the title of the image
    title = get_tag(rec_element, dc_nspace, 'title')
    rec_dict['title'] = title
    
    # Set the format of the image
    frmat = get_tag(rec_element, dc_nspace, 'format')
    rec_dict['format'] = frmat
    
    # Set the description
    desc = get_tag(rec_element, dc_nspace, 'description')
    rec_dict['description'] = desc
    
    # Set the date
    date = get_tag(rec_element, dc_nspace, 'date')
    rec_dict['date'] = date
    
    # Set the language
    lang = get_tag(rec_element, dc_nspace, 'language')
    rec_dict['language'] = lang
    
    # Set the references
    refs = get_tag(rec_element, dct_nspace, 'references')
    rec_dict['refs'] = refs
    
    # Set the source
    src = get_tag(rec_element, dc_nspace, 'source')
    rec_dict['source'] = src
    
    # Parse the collection ID from the first dct:references links
    try:
        ref_url = refs[0]
        
        url_parse = urlparse(ref_url)
        url_query = url_parse.query
        query_items = {u.split('=')[0]:u.split('=')[1] for u in url_query.split('&')}
        collection_id = query_items['collectionId']
    except:
        collection_id = ''
        
    rec_dict['collection_id'] = collection_id
    
    return rec_dict

# def get_auth(in_user='a_username'):
    # """
    # Gets the username and password for authentication from a file.
    
    # @type  in_user: str
    # @param in_user: The name of the user used to get the password from the 
                    # access.csv.
                    
    # @rtype:         tuple
    # @return:        The username and the password.
    # """

    # # Open CSV with authentication
    # if os.path.exists('access.csv'):
        # auth_f = open('access.csv', 'r')
        # lines = auth_f.readlines()
        # for line in lines:
            # line = line.replace('\n', '')
        
            # # Get the username and password
            # line_user, enc_pass = line.split(',')
            # if line_user == in_user:
                # username = line_user
                # password = base64.b64decode(enc_pass).decode("utf-8")
        
        # auth_f.close()
    
    # return username, password
    
def get_collection(in_id):
    
    query = '''<csw:GetRecordById 
	service="CSW" version="2.0.2" 
	resultType="results" startPosition="1" maxRecords="15" 
	outputFormat="application/xml" 
	outputSchema="http://www.opengis.net/cat/csw/2.0.2" 
	xmlns:csw="http://www.opengis.net/cat/csw/2.0.2" 
	xmlns:ogc="http://www.opengis.net/ogc" 
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
	xsi:schemaLocation="http://www.opengis.net/cat/csw/2.0.2 http://schemas.opengis.net/csw/2.0.2/CSW-discovery.xsd">
    <csw:Id>%s</csw:Id>
    <csw:ElementSetName>full</csw:ElementSetName>
</csw:GetRecordById>''' % in_id
    
    csw_r = send_cswrequest(query, 60.0)
    
    # Get first record from the response XML
    resp_xml = csw_r.content
    root = ElementTree.fromstring(resp_xml)
    
    record = parse_results(csw_r)
    
    return record

def get_cov(user, password, rec_id, collection_id, session=None, 
            post=False, ftp={}, timeout=60.0, silent=True):
    """
    Send a GetCoverage request to the WCS.
    
    @type  user:          str
    @param user:          The username used for the authorization of the 
                            request.
    @type  password:      str
    @param password:      The password used for the authorization of the 
                            request.
    @type  rec_id:        str
    @param rec_id:        The name of the user used to get the password from the 
                            access.csv.
    @type  collection_id: str
    @param collection_id: str
    @type  session:       requests.sessions.Session
    @param session:       An existing session with authorization (default=None).
    @type  post:          bool
    @param post:          Determines whether to use a GET request or a POST 
                            request (default=False).
    @type  ftp:           dict
    @param ftp:           A dictionary containing FTP info for the download 
                            location of the image (default=empty dictionary).
                          FTP items:
                            - 'host': FTP domain
                            - 'path': path to the file location
                            - 'user': username for the FTP authentication
                            - 'pass': password for the FTP authentication
    @type  timeout:       float
    @param timeout:       The total timeout in seconds for the request 
                            (default=60.0).
    @type  silent:        bool
    @param silent:        Determines whether to print information during 
                            process (default=True).
                            
    @rtype:               xml.etree.ElementTree.Element
    @return:              The XML results from the GetCoverage request.
    """
    
    if not silent:
        print("\nGetting coverage for record with ID %s" % rec_id)
        
    # Get the root URL for the WCS
    wcs_root = 'https://www.eodms-sgdot.nrcan-rncan.gc.ca/wes/services/WESOrder'
    
    if session is None:
        # If no session provided, create one with the provided username
        #username, password = get_auth(user)
    
        # Create a session with the authentication
        session = requests.Session()
        session.auth = (user, password)
    
    if post:
        # If post is True, create the POST XML and send the request.
        
        # The coverage ID should be '<collection ID>--<image ID>'
        cov_id = '%s--%s' % (collection_id, rec_id)
        
        # If the FTP info is provided, create the XML section for
        #   it.
        if len(ftp.values()) > 0:
            dest = '''<wos:Destination>
        <wos:FTPDestination>
            <wos:Hostname>%s</wos:Hostname>
            <wos:Path>%s</wos:Path>
            <wos:Username>%s</wos:Username>
            <wos:Password>%s</wos:Password>
        </wos:FTPDestination>
    </wos:Destination>''' % (ftp['host'], ftp['path'], ftp['user'], \
                            ftp['pass'])
        else:
            dest = ''
        
        # Create the GetCoverage XML
        getcov_post = '''<wcs:GetCoverage
    xmlns:wos="http://schema.compusult.net/services/2.6.1/WESOrder"
    xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'
    xsi:schemaLocation="http://www.opengis.net/wcs/2.0
    http://schemas.opengis.net/wcs/2.0/wcsAll.xsd"
    xmlns="http://www.opengis.net/wcs/2.0"
    xmlns:wcs="http://www.opengis.net/wcs/2.0"
    xmlns:wes="http://schema.compusult.net/services/2.6.1/WESOrder/wcs"
    service="WCS" version="2.0.1">
    <wcs:CoverageId>%s</wcs:CoverageId>
    <wcs:format>application/gml+xml</wcs:format>
    %s
</wcs:GetCoverage>''' % (cov_id, dest)

        if not silent:
            print("\nGet Coverage XML POST: %s" % getcov_post)
        
        # Send the GetCoverage request to the WCS
        wcs_getcov = session.post(url=wcs_root, data=getcov_post, \
                                    timeout=timeout)
        
    else:
    
        # Create the GetCoverage GET URL
        wcs_url = '%s/wcs?SERVICE=WCS&version=2.0.1&REQUEST=GetCoverage' \
                '&coverageId=%s&CollectionId=%s&format=application/gml+xml' % \
                (wcs_root, rec_id, collection_id)
        
        if not silent:
            print("\nGetCoverage URL: %s" % wcs_url)
        
        try:
            # Send the request to the WCS
            wcs_getcov = session.get(url=wcs_url, timeout=timeout)
        except Exception as e:
            # If an error occurs, get the error information and return it
            ex_info = sys.exc_info()
            return e
    
    if not silent:
        print("\nImage has been ordered and you should receive 2 emails.")
    
    # Parse the resultant XML
    out_xml = wcs_getcov.content.decode('utf-8')
    except_el = get_exception(out_xml, 'tree')
    
    return except_el

def get_cswPostxml(cur_val, id=None, coordinates='', 
                    max_recs=150, start=None, end=None):
    """
    Gets the POST XML for the CSW.
    
    @type  cur_val:     int
    @param cur_val:     The current value used for the start position
                            in the request.
    @type  user:        str
    @param user:        The username of the authentication.
    @type  password:    str
    @param password:    The password of the authentication.
    @type  id:          str
    @param id:          The record ID to get one image (default=None).
    @type  coordinates: str
    @param coordinates: The coordinates for the bounding box (default='').
                        Coorinates format:
                        - 'x1 y1, x2 y2, x3 y3,...'
    @type  max_recs:    int
    @param max_recs:    The maximum number of records to return (default=150).
    
    @rtype:             str
    @return:            The XML results for the CSW request.
    """
    
    if coordinates is None or coordinates == '':
        # Create empty bbox string
        bbox_str = ''
    else:
        # Parse coordinates
    
        # Split the coordinates by the comma
        coords_lst = coordinates.split(',')
        x_lst = []
        y_lst = []
        # Create a list of x values and y values
        for c in coords_lst:
            c = c.strip()
            #print("c: %s" % c)
            x, y = c.split(' ')
            x_lst.append(float(x))
            y_lst.append(float(y))
            
        # Get the min and max of each list to create the 
        #   lower and upper corners
        lower_corner = '%s %s' % (min(x_lst), min(y_lst))
        upper_corner = '%s %s' % (max(x_lst), max(y_lst))
        
        # Create the bbox XML element
        bbox_str = '''<ogc:BBOX>
                    <ogc:PropertyName>apiso:BoundingBox</ogc:PropertyName>
                    <gml:Envelope>
                        <gml:lowerCorner>%s</gml:lowerCorner>
                        <gml:upperCorner>%s</gml:upperCorner>
                    </gml:Envelope>
                </ogc:BBOX>''' % (lower_corner, upper_corner)
                        
    srch_str = '*'
    
    if id is None or id == '':
        # Create filter for the title
        filter = '''<ogc:PropertyIsLike escapeChar='\\' singleChar='?' wildCard='*'>
                        <ogc:PropertyName>apiso:title</ogc:PropertyName>
                        <ogc:Literal>%s</ogc:Literal>
                    </ogc:PropertyIsLike>''' % srch_str
    else:
        # Create filter for the specific ID
        filter = '''<ogc:PropertyIsEqualTo>
                        <ogc:PropertyName>apiso:identifier</ogc:PropertyName>
                        <ogc:Literal>%s</ogc:Literal>
                    </ogc:PropertyIsEqualTo>''' % id
    
    start_filter = ''                
    if start is not None and not start == '':
        start_filter = '''<ogc:PropertyIsGreaterThanOrEqualTo>
						<ogc:PropertyName>apiso:TempExtent_begin</ogc:PropertyName>
	                    <ogc:Literal>%s</ogc:Literal>
					</ogc:PropertyIsGreaterThanOrEqualTo>''' % start
                    
    end_filter = ''                
    if end is not None and not end == '':
        end_filter = '''<ogc:PropertyIsLessThanOrEqualTo>
						<ogc:PropertyName>apiso:TempExtent_end</ogc:PropertyName>
	                    <ogc:Literal>%s</ogc:Literal>
					</ogc:PropertyIsLessThanOrEqualTo>''' % end
    
    # Get the authentication from the access.csv file
    #username, password = get_auth(user)
    
    # # Build the SOAP start for authentication
    # soap_header = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    # <soapenv:Header>
        # <wsse:Security soapenv:mustUnderstand="1" xmlns:wsse="http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            # <wsse:UsernameToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                # <wsse:Username>%s</wsse:Username>
                # <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">%s</wsse:Password>
            # </wsse:UsernameToken>
        # </wsse:Security>
    # </soapenv:Header>
    # <soapenv:Body>
        # ''' % (user, password)
    
    # Build the XML body
    xml_body = '''<csw:GetRecords service='CSW' version='2.0.2'
    maxRecords='%s'
    startPosition='%s'
    resultType='results'
    outputFormat='application/xml'
    outputSchema='http://www.opengis.net/cat/csw/2.0.2'
    xmlns='http://www.opengis.net/cat/csw/2.0.2'
    xmlns:csw='http://www.opengis.net/cat/csw/2.0.2'
    xmlns:ogc='http://www.opengis.net/ogc'
    xmlns:ows='http://www.opengis.net/ows'
    xmlns:dc='http://purl.org/dc/elements/1.1/'
    xmlns:dct='http://purl.org/dc/terms/'
    xmlns:gml='http://www.opengis.net/gml' 
    xmlns:gmd='http://www.isotc211.org/2005/gmd' 
    xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'
    xsi:schemaLocation='http://www.opengis.net/cat/csw/2.0.2
    http://schemas.opengis.net/csw/2.0.2/CSW-discovery.xsd'>
    <csw:Query typeNames='gmd:MD_Metadata'>
        <csw:ElementSetName>full</csw:ElementSetName>
        <csw:Constraint version='1.1.0'>
            <ogc:Filter>
                <ogc:And>
                    %s
                    %s
                    %s
                    %s
                </ogc:And>
            </ogc:Filter>
        </csw:Constraint>
    </csw:Query>
</csw:GetRecords>
    ''' % (max_recs, cur_val, filter, bbox_str, start_filter, end_filter)
    
    print("xml_body: %s" % xml_body)
    
    # # Create the SOAP footer
    # soap_footer = '''</soapenv:Body>
# </soapenv:Envelope>'''
    
    # Submit a GetRecords to the CSW
    #post_xml = soap_header + xml_body + soap_footer
    post_xml = xml_body

    return post_xml
    
def get_exception(in_xml, output='str'):
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
    if in_xml is None: return None
    
    # If the input is a string, convert it to a xml.etree.ElementTree.Element
    if isinstance(in_xml, str):
        root = ElementTree.fromstring(in_xml)
    else:
        root = in_xml
    
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
                
def get_fromOrderKey(in_rec, timeout=60.0, attempts=4):
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
            res = requests.get(query_url, timeout=timeout)
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
    
    for res in results:
        # Go through each record in the results to locate the
        #   specific record with the order key
        if res['title'] == order_key:
            mdata = res['metadata2']
            
            # Create the output record dictionary and fill it
            #   with the record's metadata and the record ID
            rec = {}
            rec['id'] = res['recordId']
            rec['collection_id'] = res['collectionId']
            rec['title'] = res['title']
            
            for m in mdata:
                if m['id'] == 'CATALOG_IMAGE.START_DATETIME':
                    rec['date'] = m['value']
    
    return rec
                
def get_tag(in_el, nspace, tag, attrb=False):
    """
    Gets a tag (or tags) from an XML tree.
    
    @type  in_el:  xml.etree.ElementTree.Element
    @param in_el:  The input XML containing the element with the tag.
    @type  nspace: str
    @param nspace: The namespace to locate the element.
    @type  tag:    str
    @param tag:    The tag name of the element.
    @type  attrb:  bool
    @param attrb:  Determines whether to return the attributes of the element.
    
    @rtype:        list
    @return:       A list of the element texts with the given tag and namespace.
    """
    
    # Combine the tag with the namespace
    tag_val = '%s%s' % (nspace, tag)
    # Find all elements with the given tag
    elements = in_el.findall(tag_val)
    
    if elements is None or len(elements) == 0:
        # If the no elements found, iterate through the input XML to 
        #   locate the element
        elements = []
        for child in in_el.iter('*'):
            if child.tag.find(tag) > -1:
                el = child
                elements.append(el)
    
    if len(elements) == 1:
        # If only one element found, get the element text or its attributes
        element = elements[0]
        if attrb:
            val = element.attrib['numberOfRecordsMatched']
        else:
            val = element.text
    else:
        # If more than one element found, add its text to the output list
        val = []
        for el in elements:
            val.append(el.text)
    
    return val
    
def parse_results(xml_tree):
    """
    Parses the results of a CSW request and converts each record to a 
        dictionary.
    
    @type  xml_tree: xml.etree.ElementTree.Element
    @param xml_tree: The input XML containg the results of a CSW request.
    
    @rtype:          list
    @return:         A list of dictionaries representing each record in the 
                        CSW request.
    """
    
    # If the input XML contains an exception, return the exception as 
    #   the request returned an error.
    except_el = get_exception(xml_tree, 'tree')
    if except_el is not None: return except_el

    records = []
    
    # Go through each item with the tag 'Record' and convert the information
    #   to a dictionary using the build_record method
    record_tag = '{http://www.opengis.net/cat/csw/2.0.2}Record'
    for child in xml_tree.iter('*'):
        if child.findall(record_tag):
            # Get the element and create the record dict
            rec_elements = child.findall(record_tag)
            for r in rec_elements:
                rec = build_record(r)
                
                # Add to the records list
                records.append(rec)
            
    return records
    
def send_cswrequest(xml_post, timeout=10.0, mission='rcm'):
    """
    Sends a POST request to the CSW.
    
    @type  xml_post: str
    @param xml_post: The POST request XML.
    @type  timeout:  float
    @param timeout:  The timeout in seconds for the request.
    @type  mission:  str
    @param mission:  The mission name/acronym for the image.
                     Current options:
                     - 'rcm': queries RCM imagery
                     - 'catalog': queries the generic EODMS catalog
                     - 'napl': queries NAPL imagery
    
    @rtype:          requests.models.Response
    @return:         The XML response from the CSW request.
    """
    
    # Get the mission CSW URL based on the mission variable
    if mission.lower() == 'rcm':
        csw_url = 'https://www.eodms-sgdot.nrcan-rncan.gc.ca/MetaManagerCSW' \
                    '/csw/RCMImageProducts'
    elif mission.lower() == 'catalog':
        csw_url = 'https://www.eodms-sgdot.nrcan-rncan.gc.ca/MetaManagerCSW' \
                    '/csw/eodms_catalog'
    elif mission.lower() == 'napl':
        csw_url = 'https://www.eodms-sgdot.nrcan-rncan.gc.ca/MetaManagerCSW' \
                    '/csw/eodms_napl_catalog'
    
    # Set the header for the request
    #header = {'Content-Type':'application/xml'}
    
    # Get the CSW request
    out_resp = None
    try:
        out_resp = requests.post(csw_url, data=xml_post, timeout=timeout)
    except:
        traceback.print_exc(file=sys.stdout)
        print("out_resp: %s" % out_resp)
        
    return out_resp
    
def send_orders(in_res, user, password, timeout=60.0, session=None):
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
        if 'exception' in r.keys(): continue
        item = {"collectionId": r['collection_id'], 
                "recordId": r['id']}
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
    order_res = session.post(url=order_url, data=post_json, \
                                timeout=timeout)
    
    return order_res.json()
 
def run(user, password, in_fn=None, bbox=None, maximum=None, start=None, 
        end=None):
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
    @type  bbox:     str
    @param bbox:     The bounding box used for the query request.
    @type  maximum:  int or str
    @param maximum:  The maximum number of records to be ordered.
    @type  start:    str
    @param start:    The maximum number of records to be ordered.
    @type  end:      str
    @param end:      The maximum number of records to be ordered.
    
    @rtype:          None
    @return:         None
    """
    
    # Set defaults
    gap = 10.0
    timeout = 60.0
    
    print("\nRunning script with the following parameters:")
    print("  Gap Between Requests: %ss" % gap)
    print("  Timeout Time: %ss" % timeout)
    print("  Bounding Box: %s" % bbox)
    print("  Maximum: %s orders" % maximum)
    
    # Set variables to 0
    passes = 0
    fails = 0
    rec_count = 0
    
    # Get current timestamp for the output CSV filename
    fn_time = datetime.datetime.now()
    fn_str = fn_time.strftime("%Y%m%d_%H%M%S")
    
    print("Process started at: %s" % fn_str)
    
    if in_fn is None or in_fn == '':
        # If no input file provided by user
    
        # Create the header for the output CSV file
        header = ['Start', 'End', 'Total', 'Status', 'Records Returned']
    else:
        # Get image information from the input file
    
        # Open the input file
        in_f = open(in_fn, 'r')
        in_lines = in_f.readlines()
        
        # Get the header from the first row
        in_header = in_lines[0].replace('\n', '').split(',')
        
        # Populate the list of records from the input file
        cur_recs = []
        for l in in_lines[1:]:
            rec = {}
            l_split = l.replace('\n', '').split(',')
            for idx, h in enumerate(in_header):
                rec[h] = l_split[idx]
                
            rec['collection_id'] = "RCMImageProducts"
                
            if 'sequence_id' in rec.keys():
                # If sequence_id was provided
                rec['id'] = rec['sequence_id']
            elif 'Downlink Segment ID' in rec.keys():
                # Determine the record ID using the order key and 
                #   downlink segment ID.
                # The record ID will be used to order the image
                #   in the next step
                res = get_fromOrderKey(rec, timeout)
                if res is None:
                    # If no results found using the order key
                    rec['id'] = 'N/A'
                    rec['title'] = rec['Order Key']
                    rec['exception'] = 'The RAPI search request timed out.'
                elif isinstance(res, list):
                    rec['id'] = 'N/A'
                    rec['title'] = rec['Order Key']
                    rec['exception'] = ' '.join(res)
                else:
                    rec = res
            
            # Add the record to the list of records
            cur_recs.append(rec)
        
        # Close the input file
        in_f.close()
    
    # Create the file for the records
    orders_fn = '%s_OrderInfo.csv' % fn_str
    orders_csv = open(orders_fn, 'w')
    orders_header = ['id', 'title', 'date', 'collection_id', 'exception', \
                    'order_id', 'order_item_id', 'order_status', \
                    'time_ordered']
    orders_csv.write('%s\n' % fn_str)
    orders_csv.write('%s\n' % ','.join(orders_header))
    
    # Parse the bbox
    try:
        minx, miny, maxx, maxy = bbox.split(',')
        coords = "%s %s, %s %s" % (minx.strip(), miny.strip(), maxx.strip(), \
                                maxy.strip())
    except:
        print('\nWARNING: Issue parsing the coordinates for the ' \
                'bounding box.')
        print('No bounding box will be used for the query.')
        coords = ''
    
    if in_fn is None or in_fn == '':
        # If no file with list of record IDs provided,
        #   get the IDs from the CSW
        
        if maximum is None or maximum == '' or not maximum.isdigit():
            maximum = 10000
        else:
            maximum = int(maximum)
        
        # Get the POST XML for the CSW
        xml_post = get_cswPostxml(1, coordinates=coords, max_recs=maximum, 
                                    start=start, end=end)
        
        #print("\nxml_post: %s" % xml_post)
    
        print("\nGetting the records from the CSW...")
        
        # Send the request to the RCM CSW
        csw_r = send_cswrequest(xml_post, timeout)
            
        # Get first record from the response XML
        resp_xml = csw_r.content
        root = ElementTree.fromstring(resp_xml)
        
        #print("resp_xml: %s" % resp_xml)
        
        cur_recs = parse_results(root)
        
    
    print("\n%s records returned after querying the RAPI." % len(cur_recs))
        
    if not isinstance(cur_recs, list):
        # If the cur_recs is not a list, an error occurred.
        err_msg = cur_recs.text
        print("\nERROR: %s" % err_msg)
        if err_msg.find('Authorization required') > -1:
            print("Exiting process.")
            sys.exit(1)
    else:
        
        # If a maximum is provided, cut the current records
        #   at the maximum position
        if maximum is not None and len(cur_recs) > maximum:
            cur_recs = cur_recs[:maximum]
        
        # Send the order requests to the RAPI
        order_res = send_orders(cur_recs, user, password)
        
        for rec in cur_recs:
            
            # Get the order info for the current record
            order_info = None
            if order_res is not None:
                for o in order_res['items']:
                    if o['recordId'] == rec['id']:
                        rec['order_id'] = o['orderId']
                        rec['order_item_id'] = o['itemId']
                        rec['order_status'] = o['status']
                        cov_time = datetime.datetime.now()
                        rec['time_ordered'] = cov_time.strftime(\
                                                "%Y%m%d_%H%M%S")
        
            # Write record to CSV
            del_lst = []
            for k in rec.keys():
                if k not in orders_header:
                    del_lst.append(k)
                    
            for k in del_lst:
                del rec[k]
            
            # # Log end time of the request
            # order_end = datetime.datetime.now()
            
            # # Get the difference in time for the request
            # order_time = order_end - order_start
            
            # rec['order_time'] = str(order_time.total_seconds())
            
            # print("rec: %s" % rec)
            
            # Write the values to the output CSV file
            out_vals = []
            for h in orders_header:
                if h in rec.keys():
                    out_vals.append(rec[h])
                else:
                    out_vals.append('')
            orders_csv.write('%s\n' % ','.join(out_vals))
            
    # Get the end time for the entire process
    end_time = datetime.datetime.now()
    end_str = end_time.strftime("%Y%m%d_%H%M%S")
    
    # Add the end time to the output CSV
    orders_csv.write("%s\n" % end_str)
    orders_csv.close()
    
    print("\nProcess started at: %s" % fn_str)
    print("Process ended at: %s" % end_str)
    
    if order_res is None:
        num_orders = 0
    else:
        num_orders = len(order_res)
    print("\n%s images were ordered." % num_orders)
    
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
    
    # Log the start time of the process
    start = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Send the request to the WCS
    res = api.get_cov(user, password, image_id, 'RCMImageProducts', \
                        timeout=60.0)
    
    print("\nRecord ID: %s" % image_id)
    print("Exception: %s" % get_exception(res))
    
    # Log the end time
    end = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print("\nTimes for Describe Coverage of Record ID '%s':" % image_id)
    print("\tStart Time: %s" % start)
    print("\tEnd Time: %s" % end)

def main():

    parser = argparse.ArgumentParser(description='Order RCM products.')
    
    parser.add_argument('-u', '--username', help='The username of the ' \
                        'account used for autentication.')
    parser.add_argument('-p', '--password', help='The password of the ' \
                        'account used for autentication.')
    parser.add_argument('-b', '--bbox', help='The bounding box for the ' \
                        'search results (minx,miny,maxx,maxy).')
    parser.add_argument('-m', '--maximum', help='The maximum number of ' \
                        'orders to complete. The process will end once ' \
                        'this number of images has been ordered.')
    parser.add_argument('-s', '--start', help='The start of the date ' \
                        'range. Leave blank for no start limit.')
    parser.add_argument('-e', '--end', help='The end of the date range. ' \
                        'Leave blank for no end limit.')
    parser.add_argument('-i', '--id', help='The record ID for a single ' \
                        'image. If this parameter is entered, only the ' \
                        'image with this ID will be ordered.')
    parser.add_argument('-f', '--input', help='A CSV file containing a list ' \
                        'of record IDs. The process will only order the ' \
                        'images from this file.\nThe file should contain a ' \
                        'column called "id", "sequence_id" or "Downlink ' \
                        'Segment ID".')
    
    args = parser.parse_args()
    
    maximum = args.maximum
    user = args.username
    password = args.password
    bbox = args.bbox
    start = args.start
    end = args.end
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
        if bbox is None:
            bbox = input("Enter the bounding box for the query (format: minx," \
                        "miny,maxx,maxy): ")
                
        if maximum is None:
            maximum = input("Enter the maximum number of orders [all]: ")
            if maximum == '' or maximum.lower() == 'all':
                maximum = None
            # else:
                # if not maximum.isdigit():
                    # print("\nERROR: A whole number must be provided for the " \
                            # "'maximum' parameter.")
                    # print("Exiting process.")
                    # sys.exit(1)
                # maximum = int(maximum)
        # else:
            # maximum = int(maximum)
            
        if start is None:
            start = input("Enter the start of the date range for the orders " \
                            "(format: yyyy-mm-dd) (leave blank for no start " \
                            "limit): ")
                            
        if end is None:
            end = input("Enter the end of the date range for the orders " \
                            "(format: yyyy-mm-dd) (leave blank for no end " \
                            "limit): ")
    
    run(user, password, in_fn, bbox, maximum, start, end)

if __name__ == '__main__':
	sys.exit(main())