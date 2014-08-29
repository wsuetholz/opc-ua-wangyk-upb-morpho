<html><head><title>MySQL Table Viewer</title></head><body>
<?php
$db_host = 'localhost';
$db_user = 'root';
$db_pwd = '';

$database = 'smart_home_db';
$table = 'sensor';

if (!mysql_connect($db_host, $db_user, $db_pwd))
    die("Can't connect to database");

if (!mysql_select_db($database))
    die("Can't select database");



$showtablequery = "
	SHOW TABLES
	FROM
	smart_home_db
	";
 
$showtablequery_result	= mysql_query($showtablequery);
while($showtablerow = mysql_fetch_array($showtablequery_result))
{
	echo $showtablerow[0]."<br />";
}
?>
</body></html>