# eodms-rcm-order.py

The **eodms-rcm-order.py** script is used to order RCM images using a CSV file containing a list of RCM images or a single RCM image specified by a Record ID.

## Parameters

The script can be run on its own or with a batch file containing specific parameters. Any parameters the user does not specify will be prompted during the script.

Here is a list of parameters for the script:

| Parameter    | Tags                     | Description                                                                                                                                                                                             | 
|--------------|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Username     | <pre>-u --username</pre> | The username of the EODMS account used for authentication.                                                                                                                                              |
| Password     | <pre>-p --password</pre> | The password of the EODMS account used for authentication.                                                                                                                                              |
| Record ID    | <pre>-r --recordid</pre> | The Record ID for a single image. If this parameter is entered, only the image with this ID will be ordered.                                                                                            |
| Input        | <pre>-i --input</pre>    | A CSV file containing a list of images. The process will only order the images from this file. The file should contain a column called "**Record ID**", "**Sequence ID**" or "**Downlink Segment ID**". |

## Usage

The user must specify a username and password from an EODMS account to order RCM images.

### Import CSV File

The script will accept a CSV file containing a list of RCM images. The file can be drag-and-dropped on to the batch file "**eodms-rcm-order.bat**" or by using the flag <code>-i</code> in a command-line syntax.

The CSV file can either be created by the user or obtained by [exporting a search result](https://wiki.gccollab.ca/EODMS_How-To_Guide#Is_it_possible_to_export_the_results_including_geometry_.28i.e._spatial_info.29) from the [EODMS UI](https://www.eodms-sgdot.nrcan-rncan.gc.ca/index_en.jsp) or a manually created file.

The CSV file must contain a "**Record ID**", "**Sequence ID**" or "**Downlink Segment ID**" column. If the file contains a "**Downlink Segment ID**", it must also contain an "**Order Key**" column as well (these 2 columns are included in an exported EODMS search).

**NOTE**: The script will take longer to run if no "**Record ID**" or "**Sequence ID**" is specified since each Record ID will need to be obtained using a query to the [EODMS Rest API](https://wiki.gccollab.ca/EODMS_APIs#REST_API).

#### Example Syntax

```
python eodms-rcm-order.py -i "C:\TEMP\Record.csv"
```

### Single Image Order

The user can also submit a single order by specifying the Record ID of the RCM image. The Record ID is entered in the batch file using the flag <code>-r</code> in a command-line syntax.

#### Example Syntax

```
python eodms-rcm-order.py -r 7361332 -u username -p password
```

### Help Example

```
usage: eodms-rcm-order.py [-h] [-u USERNAME] [-p PASSWORD] [-r RECORDID]
                          [-i INPUT]

Order RCM products.

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        The username of the EODMS account used for
                        authentication.
  -p PASSWORD, --password PASSWORD
                        The password of the EODMS account used for
                        authentication.
  -r RECORDID, --recordid RECORDID
                        The record ID for a single image. If this parameter is
                        entered, only the image with this ID will be ordered.
  -i INPUT, --input INPUT
                        A CSV file containing a list of record IDs. The
                        process will only order the images from this file. The
                        file should contain a column called "Record ID",
                        "Sequence ID" or "Downlink Segment ID" with an "Order
                        Key" column.
```
