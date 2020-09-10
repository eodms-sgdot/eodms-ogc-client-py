# Ordering Images - eodms-order.py

The **eodms-order.py** script is used to order EODMS images using a CSV file containing a list of images or a single image specified by a Record ID.

## Usage

### EODMS CSV File (No Command-Line)

1. Before running the script: 
	
    a. Use the [EODMS UI](https://www.eodms-sgdot.nrcan-rncan.gc.ca/index_en.jsp), search for the images you'd like to order and [save the search results into a CSV file](https://wiki.gccollab.ca/EODMS_How-To_Guide#Is_it_possible_to_export_the_results_including_geometry_.28i.e._spatial_info.29).
		
	or
		
    b. If you already know the Record IDs of the images you'd like to order, you can create a CSV file with a "**Record ID**" and "**Collection ID**" field.
	
2. Drag-and-drop the CSV file created in the previous step onto the **eodms-order.bat**.

	**NOTE**: You can also run the batch file without the drag-and-drop, however you will be prompted for the CSV file after entering your username and password (after step 3).

3. You will be prompted for a username and password. Enter the username and password of your EODMS account.

4. If the collection name cannot be determined from the **Satellite** column in the CSV file, you will be prompted to select the collection from a list of available collections for your account.

5. Once complete, a CSV file will be created in the script folder with the date/time and "_OrderInfo" appended (ex: **20200909_114550_OrderInfo.csv**)

### Single Image Order

You can also submit a single order by specifying the **Record ID** of an image.

1. Double-click on the **eodms-order.bat** file.

2. Enter your username and password when prompted.

3. You will be asked to enter either the CSV file or a Record ID. In this case, enter a **Record ID**.

4. Enter the respective number for the collection from the list of available collections.

5. Once complete, a CSV file with the single order will be created in the script folder with the date/time and "_OrderInfo" appended (ex: **20200909_114550_OrderInfo.csv**)

## Parameters

The script can be run on its own or with a batch file containing specific parameters. Any parameters you do not specify will be prompted during the script.

Here is a list of parameters for the script:

| Parameter    | Tags                       | Description                                                                                                                                                                                             | 
|--------------|----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Username     | <pre>-u --username</pre>   | The username of the EODMS account used for authentication.                                                                                                                                              |
| Password     | <pre>-p --password</pre>   | The password of the EODMS account used for authentication.                                                                                                                                              |
| Record ID    | <pre>-r --recordid</pre>   | The Record ID for a single image. If this parameter is entered, only the image with this ID will be ordered.                                                                                            |
| Input        | <pre>-i --input</pre>      | A CSV file containing a list of images. The process will only order the images from this file. The file should contain a column called "**Record ID**", "**Sequence ID**" or "**Downlink Segment ID**". |
| Collection   | <pre>-c --collection</pre> | The collection of the images being ordered.

### Syntax Examples

#### Setting Input CSV File

```
python eodms-order.py -i "C:\TEMP\Record.csv"
```

#### Single Image Order

```
python eodms-order.py -r 7361332 -u <username> -p <password>
```

## Help Example

```
usage: eodms-order.py [-h] [-u USERNAME] [-p PASSWORD] [-r RECORDID]
                      [-i INPUT] [-c COLLECTION]

Order EODMS products.

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
  -c COLLECTION, --collection COLLECTION
                        The collection of the images being ordered.
```

# Downloading Orders - eodms-download-orders.py

The **eodms-download-orders.py** script is used to download images which were ordered using the eodms-order.py script in the [previous section](#ordering-images---eodms-orderpy).

## Usage

1. Before running this script, order a set of images using the eodms-order.py script (see [Ordering Images - eodms-order.py](#ordering-images---eodms-orderpy)). The output CSV file from that script (\<date\>_OrderInfo.csv file) is used in this script to download ordered images.

2. Drag-and-drop the CSV file onto **eodms-download-orders.bat**.

3. When prompted enter your username and password.

4. The process will:

	a. If the images are available for download, they will be downloaded to the ***downloads*** folder in the same location as the script (the folder with automatically be created).
	
	b. If the downloads are not ready, you will be informed that the images aren't ready and that you will receive an **"EODMS Image Request Delivery Notification"** email when their images are ready.
	
	c. If the images have failed, you will be informed of the reason and be notified that you received an **"EODMS Image Request Failed Notification"** email.

## Parameters

The script can be run on its own or with a batch file containing specific parameters. You will be prompted for any parameters which were not entered in a batch file.

Here is a list of parameters for the script:

| Parameter | Tags                     | Description                                                 |
|-----------|--------------------------|-------------------------------------------------------------|
| Username  | <pre>-u --username</pre> | The username of the EODMS account used for authentication.  |
| Password  | <pre>-p --password</pre> | The password of the EODMS account used for authentication.  |
| Input     | <pre>-i --input</pre>    | The OrderInfo CSV file exported from eodms-order.py script. |

### Syntax Examples

```
python eodms-download-orders.py -i 20200909_163026_OrderInfo.csv -u <username> -p <password>
```

## Help Example

```
usage: eodms-download-orders.py [-h] [-u USERNAME] [-p PASSWORD] [-i INPUT]

Download EODMS images from a CSV file exported using eodms-order.py.

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        The username of the EODMS account used for
                        authentication.
  -p PASSWORD, --password PASSWORD
                        The password of the EODMS account used for
                        authentication.
  -i INPUT, --input INPUT
                        The OrderInfo CSV file exported from eodms-order.py
                        script.
```