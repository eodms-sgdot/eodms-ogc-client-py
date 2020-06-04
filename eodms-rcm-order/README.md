# eodms-rcm-order.py

The eodms-rcm-order.py script is used to order images based on a set of coordinates (bounding box) provided by the user. 

## Script Arguments

The user provides their account information (username and password), a set of coordinates (format: minx,miny,maxx,maxy) and the maximum number of records to order. Any arguments which are not entered in the batch file, the user will be prompted for these arguments at the start of the script.

There are 2 arguments that are only entered from the batch file:
* The ID will be used to order a single image (except for the account information, no other arguments are required).
* The Input argument is used to enter a CSV file with a list of images to order (except for the account information, no other arguments are required).<br>
The CSV file should have the following headers and columns:
  * id,title,date,collection_id

### Help

```
usage: eodms-rcm-order.py [-h] [-u USERNAME] [-p PASSWORD] [-b BBOX]
                          [-m MAXIMUM] [-s START] [-e END] [-i ID] [-f INPUT]

Order RCM products.

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        The username of the account used for autentication.
  -p PASSWORD, --password PASSWORD
                        The password of the account used for autentication.
  -b BBOX, --bbox BBOX  The bounding box for the search results
                        (minx,miny,maxx,maxy).
  -m MAXIMUM, --maximum MAXIMUM
                        The maximum number of orders to complete. The process
                        will end once this number of images has been ordered.
  -s START, --start START
                        The start of the date range. Leave blank for no start
                        limit.
  -e END, --end END     The end of the date range. Leave blank for no end
                        limit.
  -i ID, --id ID        The record ID for a single image. If this parameter is
                        entered, only the image with this ID will be ordered.
  -f INPUT, --input INPUT
                        A CSV file containing a list of record IDs. The
                        process will only order the images from this file. The
                        file should contain the header and columns:
                        id,title,date,collection_id
```
