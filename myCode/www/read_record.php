<?php
error_reporting(E_ALL ^ E_DEPRECATED);
/*
 * Following code will list all the products
 */

// array for JSON response
$response = array();
if (isset($_GET['tst'])) {
require_once __DIR__ . '/db_config.php';
$con = @mysql_connect(DB_SERVER, DB_USER, DB_PASSWORD) or die("Error " . mysql_error($link));
@mysql_select_db(DB_DATABASE);

// get all products from products table
$result = mysql_query("SELECT *FROM secure_record") or die(mysql_error());

// check for empty result
if (mysql_num_rows($result) > 0) {
    // looping through all results
    // products node
    $response["record"] = array();
    
    while ($row = mysql_fetch_array($result)) {
        // temp user array
        $record = array();
        $record["user_id"] = $row["user_id"];
        $record["activity"] = $row["activity"];
        $record["date"] = $row["date"];

        // push single product into final response array
        array_push($response["record"], $record);
    }
    // success
    $response["success"] = 1;

    // echoing JSON response
    echo json_encode($response);
} else {
    // no products found
    $response["success"] = 0;
    $response["message"] = "No Results found";

    // echo no users JSON
    echo json_encode($response);
}
}
?>
