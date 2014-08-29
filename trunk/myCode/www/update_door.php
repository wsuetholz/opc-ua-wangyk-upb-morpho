<?php
error_reporting(E_ALL ^ E_DEPRECATED);
/*
 * Following code will update a product information
 * A product is identified by product id (pid)
 */

// array for JSON response
$response = array();

// check for required fields
if (isset($_GET['user_id']) && isset($_GET['access_right'])) {

	
    $Name = $_GET['user_id'];
    $Right = $_GET['access_right'];
	
    // connecting to db
	require_once __DIR__ . '/db_config.php';
	$con = @mysql_connect(DB_SERVER, DB_USER, DB_PASSWORD) or die("Error " . mysql_error($link));
	@mysql_select_db(DB_DATABASE);
	
    // mysql update row with matched name
    $result = mysql_query("INSERT IGNORE INTO main_lock (user_id, access_right) VALUES ( '$Name', '$Right')");
	
    // check if row inserted or not
    if ($result) {
        // successfully updated
        $response["success"] = 1;
        $response["message"] = "Main doorLock Configuration updated.";
        
        // echoing JSON response
        echo json_encode($response);
    } else {
        
    }
} else {
    // required field is missing
	
    $response["success"] = 0;
    $response["message"] = "Required field(s) is missing";

    // echoing JSON response
    echo json_encode($response);
}
?>
