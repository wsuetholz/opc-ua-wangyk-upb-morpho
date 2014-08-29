<?php
error_reporting(E_ALL ^ E_DEPRECATED);
/*
 * Following code will update a product information
 * A product is identified by product id (pid)
 */

// array for JSON response
$response = array();

// check for required fields
if (isset($_GET['Name'])) {


    $Name = $_GET['Name'];
    // connecting to db

	require_once __DIR__ . '/db_config.php';
	$con = @mysql_connect(DB_SERVER, DB_USER, DB_PASSWORD) or die("Error " . mysql_error($link));
	@mysql_select_db(DB_DATABASE);
	
    // mysql update row with matched name
    $result = mysql_query("SELECT * FROM sensor WHERE Name = '$Name'");
	
    if (!empty($result)) {
         if (mysql_num_rows($result) > 0) {

            $result = mysql_fetch_array($result);

            $product = array();
            $product["CurrentValue"] = $result["CurrentValue"];
            // success
            // user node
            $response["success"] = 1;
            $response["TempSensor"] = $result["CurrentValue"];

           // array_push($response["TempSensor"], $product);

            // echoing JSON response
          //  header('Content-Type: application/json');
            echo json_encode($response);
        } else {
            // no product found
            $response["success"] = 0;
            $response["message"] = "empty in result";

            // echo no users JSON
            echo json_encode($response);
        }
    } else {
        // no product found
        $response["success"] = 0;
        $response["message"] = "result empty";

        // echo no users JSON
        echo json_encode($response);
    }
} else {
    // required field is missing
    $response["success"] = 0;
    $response["message"] = "Required field(s) is missing";

    // echoing JSON response
    echo json_encode($response);
}
?>