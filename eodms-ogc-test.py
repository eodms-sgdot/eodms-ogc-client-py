import sys
import requests
from xml.etree import ElementTree
import base64
from urllib.parse import urlencode
from urllib.parse import urlparse

def main():

    # Set specific parameters
    aoi = '-76.3556 44.9617 -75.2466 44.9617 -75.2466 45.5371 ' \
            '-76.3556 45.5371 -76.3556 44.9617'
    lower_corner = '-76.3556 44.9617'
    upper_corner = '-75.2466 45.5371'
    end_date = '2013-03-29Z'

    # Submit a GetRecords to the CSW
    post_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<csw:GetRecords service='CSW' version='2.0.2'
    maxRecords='15'
    startPosition='1'
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
    xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'
    xsi:schemaLocation='http://www.opengis.net/cat/csw/2.0.2
    http://schemas.opengis.net/csw/2.0.2/CSW-discovery.xsd'>
    <csw:Query typeNames='csw:Record'>
        <csw:ElementSetName typeNames='csw:Record'>full</csw:ElementSetName>
        <csw:Constraint version="1.1.0">
            <ogc:Filter>
                <ogc:And>
                    <ogc:PropertyIsLessThan>
                        <ogc:PropertyName>dc:date</ogc:PropertyName>
                        <ogc:Literal>%s</ogc:Literal>
                    </ogc:PropertyIsLessThan>
                    <ogc:PropertyIsLike escapeChar='\\' singleChar='?' wildCard='*'>
                        <ogc:PropertyName>dc:title</ogc:PropertyName>
                        <ogc:Literal>*</ogc:Literal>
                    </ogc:PropertyIsLike>
                    <ogc:BBOX>
                        <ogc:PropertyName>ows:BoundingBox</ogc:PropertyName>
                        <gml:Envelope>
                            <gml:lowerCorner>%s</gml:lowerCorner>
                            <gml:upperCorner>%s</gml:upperCorner>
                        </gml:Envelope>
                    </ogc:BBOX>
                </ogc:And>
         </ogc:Filter>
        </csw:Constraint>
    </csw:Query>
</csw:GetRecords>''' % (end_date, lower_corner, upper_corner)

    csw_url = 'https://www.eodms-sgdot.nrcan-rncan.gc.ca/MetaManagerCSW' \
                '/csw/eodms_catalog'
    headers = {'Content-Type':'application/xml'}
    csw_r = requests.post(csw_url, data=post_xml)
        
    # Get first record from the response XML
    resp_xml = csw_r.content
    root = ElementTree.fromstring(resp_xml)
    
    record_tag = '{http://www.opengis.net/cat/csw/2.0.2}Record'
    for child in root.iter('*'):
        if child.find(record_tag):
            rec_element = child.find(record_tag)
            break
    
    # Get the ID of the first record
    id_tag = '{http://purl.org/dc/elements/1.1/}identifier'
    id_el = rec_element.find(id_tag)
    rec_id = id_el.text
    
    # Parse the collection ID from the first dct:references links
    ref_tag = '{http://purl.org/dc/terms/}references'
    ref_el = rec_element.find(ref_tag)
    ref_url = ref_el.text
    
    url_parse = urlparse(ref_url)
    url_query = url_parse.query
    query_items = {u.split('=')[0]:u.split('=')[1] \
                  for u in url_query.split('&')}
    collection_id = query_items['collectionId']
    
    # Submit a DescribeCoverage GET request to the WCS using the record 
    #   and collection IDs
    wcs_url = 'https://www.eodms-sgdot.nrcan-rncan.gc.ca/wes/services/WESOrder/' \
            'wcs?SERVICE=WCS&version=2.0.1&REQUEST=DescribeCoverage' \
            '&coverageId=%s&CollectionId=%s' % (rec_id, collection_id)
    
    # Create a session with authentication
    username = 'keballan'
    password = base64.b64decode("TWJWbUNoMTIj").decode("utf-8")
    
    session = requests.Session()
    session.auth = (username, password)
    wcs_desccov = session.get(url=wcs_url)
    
    if wcs_desccov.status_code == 200:
    
        cov_id = '%s--%s' % (collection_id, rec_id)
    
        # Submit a GetCoverage to the WCS
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
</wcs:GetCoverage>''' % cov_id

        wcs_getcov = session.post(url=wcs_url, data=getcov_post)

if __name__ == '__main__':
    sys.exit(main())