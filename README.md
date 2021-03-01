# eodms-ogc-client-py

## End-to-End Order Example (using Python)

The following steps use Python to search the EODMS_Catalog CSW and WCS services to order a Radarsat-1 image from the EODMS.

For this example, the following restrictions will be place on the query:

* A bounding box surrounding the City of Ottawa city limits with coordinates:<br>
<code>lower corner: -76.3556 44.9617</code><br>
<code>upper corner: -75.2466 45.5371</code><br>

* All dates before to March 29, 2013 as this was the last day Radarsat-1 transmitted data

## Python Packages

The only Python package that needs to be installed prior running these scripts is the Requests package (https://realpython.com/python-requests/). It can be installed by running the command ```pip install requests```.

## GetRecords POST Request

### Set Variables

First step is to set the input parameters (restrictions listed above) for the ```GetRecords``` request.

Python code:

```python
# Set specific parameters
lower_corner = '-76.3556 44.9617'
upper_corner = '-75.2466 45.5371'
end_date = '2013-03-29Z'
```

For RCM, remove the ```end_date``` variable as there's no need for a date limit.

### Create XML Request

Next, create the XML POST GetRecords request with the above variables. The request tells the CSW to return the first 15 records based on these variables (or search criteria). NOTE: To change the number of records returned, change the maxRecords attribute in the XML below to the desired value.

GetRecords POST request example:

```xml
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
                        <ogc:Literal>2013-03-29Z</ogc:Literal>
                    </ogc:PropertyIsLessThan>
                    <ogc:PropertyIsLike escapeChar='\\' singleChar='?' 
                        wildCard='*'>
                        <ogc:PropertyName>dc:title</ogc:PropertyName>
                        <ogc:Literal>*</ogc:Literal>
                    </ogc:PropertyIsLike>
                    <ogc:BBOX>
                        <ogc:PropertyName>ows:BoundingBox</ogc:PropertyName>
                        <gml:Envelope>
                            <gml:lowerCorner>-76.3556 44.9617</gml:lowerCorner>
                            <gml:upperCorner>-75.2466 45.5371</gml:upperCorner>
                        </gml:Envelope>
                    </ogc:BBOX>
                </ogc:And>
         </ogc:Filter>
        </csw:Constraint>
    </csw:Query>
</csw:GetRecords>
```

Getting records for RCM images requires authentication using your EODMS credentials and SOAP Envelope XML:

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
	<soapenv:Header>
		<wsse:Security soapenv:mustUnderstand="1" xmlns:wsse="http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
			<wsse:UsernameToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
				<wsse:Username>eodms-username</wsse:Username>
				<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">eodms-password</wsse:Password>
			</wsse:UsernameToken>
		</wsse:Security>
	</soapenv:Header>
	<soapenv:Body>
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
							<ogc:PropertyIsLike escapeChar='\\' singleChar='?' 
								wildCard='*'>
								<ogc:PropertyName>dc:title</ogc:PropertyName>
								<ogc:Literal>*</ogc:Literal>
							</ogc:PropertyIsLike>
							<ogc:BBOX>
								<ogc:PropertyName>ows:BoundingBox</ogc:PropertyName>
								<gml:Envelope>
									<gml:lowerCorner>-76.3556 44.9617</gml:lowerCorner>
									<gml:upperCorner>-75.2466 45.5371</gml:upperCorner>
								</gml:Envelope>
							</ogc:BBOX>
						</ogc:And>
				 </ogc:Filter>
				</csw:Constraint>
			</csw:Query>
		</csw:GetRecords>
	</soapenv:Body>
</soapenv:Envelope>
```

Python code of request:

```python
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
                    <ogc:PropertyIsLike escapeChar='\\' singleChar='?' 
                        wildCard='*'>
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
```

Python code for RCM requests:

```python
# Submit a GetRecords to the CSW

post_xml = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
	<soapenv:Header>
		<wsse:Security soapenv:mustUnderstand="1" xmlns:wsse="http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
			<wsse:UsernameToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
				<wsse:Username>eodms-username</wsse:Username>
				<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">eodms-password</wsse:Password>
			</wsse:UsernameToken>
		</wsse:Security>
	</soapenv:Header>
	<soapenv:Body>
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
							<ogc:PropertyIsLike escapeChar='\\' singleChar='?' 
								wildCard='*'>
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
		</csw:GetRecords>
	</soapenv:Body>
</soapenv:Envelope>''' % (lower_corner, upper_corner)
```

### Send the Request

The next step is to send the request to the CSW URL.

For RCM, send queries to https://www.eodms-sgdot.nrcan-rncan.gc.ca/MetaManagerCSW/csw/RCMImageProducts.

For all other Radar products, send queries to https://www.eodms-sgdot.nrcan-rncan.gc.ca/MetaManagerCSW/csw/eodms_catalog.

In Python, use the requests object to send a POST request:

```python
csw_url = 'https://www.eodms-sgdot.nrcan-rncan.gc.ca/MetaManagerCSW' \
            '/csw/eodms_catalog'
headers = {'Content-Type':'application/xml'}
csw_r = requests.post(csw_url, data=post_xml)
```

Code for RCM request:
```python
csw_url = 'https://www.eodms-sgdot.nrcan-rncan.gc.ca/MetaManagerCSW' \
			'/csw/RCMImageProducts'
headers = {'Content-Type':'application/xml'}
csw_r = requests.post(csw_url, data=post_xml)
```

The GetRecords response will contain all the records up to the maxRecords value (in this case the first 15). The following HTTP response will be returned from the CSW:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<GetRecordsResponse xmlns="http://www.opengis.net/cat/csw/2.0.2">
    <SearchStatus timestamp="2019-11-22T04:11:02-05:00"/>
    <SearchResults numberOfRecordsMatched="705" 
        numberOfRecordsReturned="15" nextRecord="16">
        <csw:Record xmlns:csw="http://www.opengis.net/cat/csw/2.0.2" 
            xmlns:ows="http://www.opengis.net/ows" 
            xmlns:dct="http://purl.org/dc/terms/" 
            xmlns:dc="http://purl.org/dc/elements/1.1/">
            <dc:identifier>1508208</dc:identifier>
            <dc:title>Radarsat-1 Raw Scenes</dc:title>
            <dc:type>dataset</dc:type>
            <dc:subject>Satellites, Imaging,Radar, Digital Collection, 
                Mapping, Spatial Data, Remote Sensing
            </dc:subject>
            <dc:subject>F2</dc:subject>
            <dc:format>GeoTIFF</dc:format>
            <dc:creator>Government of Canada; Natural Resources Canada; 
                Earth Sciences Sector; Canada Centre for Mapping and 
                Earth Observation
            </dc:creator>
            <dc:description>The Radarsat-1 satellite has a synthetic 
                aperture radar(SAR) imaging instrument. The images are 
                used internationally to manage and monitor the Earth's 
                resources and to monitor global climate change, as well 
                as in many other commercial and scientific applications. 
                RADARSAT-1 is ideally suited to supporting these tasks 
                because of its wide range of beams, SAR technology, 
                frequent revisit period, high-quality products and fast, 
                efficient delivery. Each of Radarsat-1's seven beam 
                modes offer a different image resolution. The modes 
                include Fine, which covers an area of 50 km × 50 km 
                (31 mi × 31 mi) (2,500 km2 (970 sq mi)) with a resolution 
                of 10 metres (33 ft); Standard, which covers an area of 
                100 km × 100 km (62 mi × 62 mi) (10,000 km2 (3,900 sq mi)) 
                and has a resolution of 30 metres (98 ft); and ScanSAR 
                wide, which covers a 500 km × 500 km (310 mi × 310 mi) 
                (250,000 km2 (97,000 sq mi)) area with a resolution of 
                100 metres (330 ft). Radarsat-1 also has the unique 
                ability to direct its beam at different angles.
            </dc:description>
            <dct:abstract>The Radarsat-1 satellite has a synthetic 
                aperture radar(SAR) imaging instrument. The images are 
                used internationally to manage and monitor the Earth's 
                resources and to monitor global climate change, as well 
                as in many other commercial and scientific applications. 
                RADARSAT-1 is ideally suited to supporting these tasks 
                because of its wide range of beams, SAR technology, 
                frequent revisit period, high-quality products and fast, 
                efficient delivery. Each of Radarsat-1's seven beam 
                modes offer a different image resolution. The modes 
                include Fine, which covers an area of 50 km × 50 km 
                (31 mi × 31 mi) (2,500 km2 (970 sq mi)) with a resolution 
                of 10 metres (33 ft); Standard, which covers an area of 
                100 km × 100 km (62 mi × 62 mi) (10,000 km2 (3,900 sq mi)) 
                and has a resolution of 30 metres (98 ft); and ScanSAR 
                wide, which covers a 500 km × 500 km (310 mi × 310 mi) 
                (250,000 km2 (97,000 sq mi)) area with a resolution of 
                100 metres (330 ft). Radarsat-1 also has the unique 
                ability to direct its beam at different angles.
            </dct:abstract>
            <dc:publisher>NRCan/CCMEO/EODMS section head</dc:publisher>
            <dc:date>2013-02-21</dc:date>
            <dc:language>eng; CAN</dc:language>
            <dct:references scheme="OVERVIEW">
                https://was-eodms.compusult.net/wes/getObject?
                FeatureID=SERVICE-RSAT1_001-000000000000000000-1508208
                &amp;ObjectType=Thumbview&amp;collectionId=Radarsat1
            </dct:references>
            <dct:references scheme="THUMBVIEW">
                https://was-eodms.compusult.net/wes/getObject?
                FeatureID=SERVICE-RSAT1_001-000000000000000000-1508208
                &amp;ObjectType=Thumbview&amp;collectionId=Radarsat1
            </dct:references>
            <dct:references scheme="transferOptions">
                http://gs.mdacorporation.com/SatelliteData/
                Radarsat1/Radarsat1.aspx
            </dct:references>
            <dct:references scheme="transferOptions">
                http://ceocat.ccrs.nrcan.gc.ca
            </dct:references>
            <dc:source>
                https://www.eodms-sgdot.nrcan-rncan.gc.ca:80/MetaManagerCSW
                /csw/eodms_catalog?service=CSW&amp;request=GetRecordById
                &amp;version=2.0.2&amp;ElementSetName=full&amp;outputSchema=http://
                www.isotc211.org/2005/gmd&amp;Id=1508208&amp;outputFormat=text/html
            </dc:source>
            <ows:BoundingBox>
                <ows:LowerCorner>-76.275153 45.191208</ows:LowerCorner>
                <ows:UpperCorner>-75.444661 45.739692</ows:UpperCorner>
            </ows:BoundingBox>
        </csw:Record>
        <csw:Record xmlns:csw="http://www.opengis.net/cat/csw/2.0.2" 
            xmlns:ows="http://www.opengis.net/ows" 
            xmlns:dct="http://purl.org/dc/terms/" 
            xmlns:dc="http://purl.org/dc/elements/1.1/">
            .
            .
            .
        </csw:Record>
        .
        .
        .
    </SearchResults>
</GetRecordsResponse>
```

### Extract Record ID and Collection ID From Response

Using the GetRecords HTTP response, the record ID and the collection ID can be extracted. The record ID is taken from ```<dc:identifier>``` in the response. The collection ID can be extracted by parsing the URL in the ```<dct:references>```. The next step in the script is to convert the XML response into an ElementTree and get the XML element of the first record (or remove the ```break``` and add each ```rec_element``` to a list to go through each record in the response):

```python
record_tag = '{http://www.opengis.net/cat/csw/2.0.2}Record'
for child in root.iter('*'):
    if child.find(record_tag):
        rec_element = child.find(record_tag)
        break
```

Using the record element, locate the ```<dc:identifier>``` element and get its text:

```python
# Get the ID of the first record
id_tag = '{http://purl.org/dc/elements/1.1/}identifier'
id_el = rec_element.find(id_tag)
rec_id = id_el.text
```

Next, locate the ```<dct:references>``` in the record element and parse the URL from it:

```python
url_parse = urlparse(ref_url)
url_query = url_parse.query
query_items = {u.split('=')[0]:u.split('=')[1] for u in url_query.split('&')}
collection_id = query_items['collectionId']
```

## DescribeCoverage Request

The DescribeCoverage feature can be sent as a POST or GET request.

The URL for the ```DescribeCoverage``` GET request is: https://www.eodms-sgdot.nrcan-rncan.gc.ca/wes/services/WESOrder/wcs?SERVICE=WCS&version=2.0.1&REQUEST=DescribeCoverage&coverageId=1508208&CollectionId=Radarsat1

The POST request would be:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<wcs:DescribeCoverage service="WCS" version="2.0.1"
    xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'
    xsi:schemaLocation="http://www.opengis.net/wcs/2.0
    http://schemas.opengis.net/wcs/2.0/wcsAll.xsd"
    xmlns="http://www.opengis.net/wcs/2.0"
    xmlns:wcs="http://www.opengis.net/wcs/2.0">
    <wcs:CoverageId>Radarsat1--5117806</wcs:coverageid>
</wcs:describecoverage>
```

For the Python scripts, the GET URL will be used. The code for the DescribeCoverage GET URL is:

```python
# Submit a DescribeCoverage GET request to the WCS using the record and collection IDs
wcs_url = 'https://www.eodms-sgdot.nrcan-rncan.gc.ca/wes/services/WESOrder/' \
    'wcs?SERVICE=WCS&version=2.0.1&REQUEST=DescribeCoverage' \
    '&coverageId=%s&CollectionId=%s' % (rec_id, collection_id)
```
    
Using the WCS service requires a user account. To send an authenticated request in Python, a session containing the username and password has to be created first. The following code creates a session with username and password and then sends the GET request through the session:

```python
session = requests.Session()
session.auth = (username, password)
wcs_desccov = session.get(url=wcs_url)
```

Next, the DescribeCoverage will send back the following response if the request was successful:

```xml
<wcs:CoverageDescriptions xmlns:wcs="http://www.opengis.net/wcs/2.0">
    <wcs:CoverageDescription xmlns:gml="http://www.opengis.net/gml/3.2" 
        gml:id="Cd5a023dc-0003-4ddf-b5cc-5d2e533eac05">
        <wcs:CoverageId>Radarsat1--1508208</wcs:coverageid>
        <metadata xmlns="http://www.opengis.net/gmlcov/1.0" 
            xmlns:xlink="http://www.w3.org/1999/xlink" 
            xlink:href="https://www.eodms-sgdot.nrcan-rncan.gc.ca/wes
            /services/WESSearch/csw/Radarsat1?request=GetRecordById
            &Id=1508208&version=2.0.2&outputSchema=http://schema.compusult.net/
            services/2.2.0/WESSearch/csw&service=CSW" 
            xlink:title="CSW GetRecordById" 
            xlink:type="simple"/>
        <gml:domainSet>
            <gml:Polygon xmlns:gml="http://www.opengis.net/gml/3.2" 
            gml:id="C49b46f31-cbe9-433b-9201-d4f0cc04ee0d" 
            srsDimension="2" srsName="EPSG:4326">
                <gml:exterior>
                    <gml:LinearRing>
                        <gml:posList>
                            -76.275153 45.652944 
                            -76.157606 45.191208 
                            -75.444661 45.278003 
                            -75.556206 45.739692 
                            -76.275153 45.652944
                        </gml:poslist>
                    </gml:linearring>
                </gml:exterior>
            </gml:polygon>
        </gml:domainset>
        <rangeType xmlns="http://www.opengis.net/gmlcov/1.0"/>
        <wcs:ServiceParameters>
            <wcs:CoverageSubtype>GridCoverage</wcs:coveragesubtype>
            <wcs:nativeFormat/>
            <wcs:Extension>
                <DestinationTypes xmlns="http://schema.compusult.net/
                    services/2.7.0/WESOrder/wcs">
                    <Type>Download</type>
                </destinationtypes>
                <Parameter xmlns="http://schema.compusult.net/services/
                    2.7.0/WESOrder">
                    <Name>packagingFormat</name>
                    <Title>Packaging Format</title>
                    <Description>Packaging Format</description>
                    <Default>ZIP</default>
                    <Choices>
                        <Value>ZIP</value>
                        <Display>Zip</display>
                        <Description>Zip</description>
                        <DependentParameters/>
                    </choices>
                    <Choices>
                        <Value>TAR</value>
                        <Display>Tar</display>
                        <Description>Tar</description>
                        <DependentParameters/>
                    </choices>
                    <Choices>
                        <Value>TARGZ</value>
                        <Display>Tar/GZ</display>
                        <Description>Tar/GZ</description>
                        <DependentParameters/>
                    </choices>
                    <Choices>
                        <Value>TAR</value>
                        <Display>Tar</display>
                        <Description>Tar</description>
                        <DependentParameters/>
                    </choices>
                    <Choices>
                        <Value>TARGZ</value>
                        <Display>Tar/GZ</display>
                        <Description>Tar/GZ</description>
                        <DependentParameters/>
                    </choices>
                </parameter>
            </wcs:extension>
        </wcs:serviceparameters>
    </wcs:coveragedescription>
</wcs:coveragedescriptions>
```

## GetCoverage Request

If the request was successful, the status code of 200 will be returned with the request and the ```GetCoverage``` operation can be sent to the WCS. A GET request similar to the DescribeCoverage can be sent to the WCS (adding ```format=applicationgml+xml``` to the URL query).

In this case, a POST request is used. For the POST request, the ```CoverageId``` must be in the format of ```[collection]--[record_id]``` so in this case the CoverageId is ```Radarsat1--1508208```:

```xml
<wcs:GetCoverage
	xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'
	xsi:schemaLocation="http://www.opengis.net/wcs/2.0
	http://schemas.opengis.net/wcs/2.0/wcsAll.xsd"
	xmlns="http://www.opengis.net/wcs/2.0"
	xmlns:wcs="http://www.opengis.net/wcs/2.0"
	service="WCS"
	version="2.0.1">
	<wcs:CoverageId>Radarsat1--5117806</wcs:CoverageId>
	<wcs:format>application/gml+xml</wcs:format>
</wcs:GetCoverage>
```

The Python code should look something like this:

```python
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

	wcs_getcov = session.post(url=wcs_url, data=getcov_post)</pre>
	
elif wcs_desccov.status_code == 401:
        
        print("\nUnauthorized access to the WCS.")
```

Once the request has been sent, the user will receive an “EODMS Image Request Submitted Notification” email letting them know that their request has been submitted. Shortly after receiving this email, the user should then receive another email called “EODMS Image Request Delivery Notification” with download links for the specific image.
