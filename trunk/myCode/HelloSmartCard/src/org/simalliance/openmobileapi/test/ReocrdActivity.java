package org.simalliance.openmobileapi.test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.app.ListActivity;
import android.app.ProgressDialog;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.SimpleAdapter;
import android.widget.TextView;


public class ReocrdActivity extends ListActivity{
	
	// Progress Dialog
		private ProgressDialog pDialog;

		// Creating JSON Parser object
		JSONParser jParser = new JSONParser();

		ArrayList<HashMap<String, String>> recordList;

		// url to get all products list
		private static final String url_read_record ="http://10.133.68.27/read_record.php";

		// JSON Node names
		private static final String TAG_SUCCESS = "success";
		private static final String TAG_RECORD = "record";
		private static final String TAG_UID = "user_id";
		private static final String TAG_AC = "activity";
		private static final String TAG_DATA = "date";
		
		// products JSONArray
		JSONArray record = null;

		@Override
		public void onCreate(Bundle savedInstanceState) {
			super.onCreate(savedInstanceState);
			setContentView(R.layout.record);
			Log.d("Smart Home","===========get record=================");	
			// Hashmap for ListView
			recordList = new ArrayList<HashMap<String, String>>();

			List<NameValuePair> params = new ArrayList<NameValuePair>();
			params.add(new BasicNameValuePair("tst", "tst"));
			// getting JSON string from URL
			JSONObject json = jParser.makeHttpRequest(url_read_record, "GET", params);
			Log.d("Smart Home: ", json.toString());
			
			// Loading products in Background Thread
			LoadAllProducts load = new LoadAllProducts();
			load.execute();
			
			Log.d("Smart Home",recordList.toString());	
			// Get listview
			ListView lv = getListView();
			// on seleting single product
			// launching Edit Product Screen
			
			

		}
		
		/**
		 * Background Async Task to Load all product by making HTTP Request
		 * */
		class LoadAllProducts extends AsyncTask<String, String, String> {

			/**
			 * Before starting background thread Show Progress Dialog
			 * */
			@Override
			protected void onPreExecute() {
				super.onPreExecute();
			}

			/**
			 * getting All products from url
			 * */
			protected String doInBackground(String... args) {
				// Building Parameters
				List<NameValuePair> params = new ArrayList<NameValuePair>();
				params.add(new BasicNameValuePair("tst", "tst"));
				// getting JSON string from URL
				JSONObject json = jParser.makeHttpRequest(url_read_record, "GET", params);
				
				// Check your log cat for JSON reponse
				try {
					Log.d("Smart Home: ", json.get(TAG_RECORD).toString());
				} catch (JSONException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

				try {
					// Checking for SUCCESS TAG
					int success = json.getInt(TAG_SUCCESS);

					if (success == 1) {
						// products found
						// Getting Array of Products
						record = json.getJSONArray(TAG_RECORD);

						// looping through All Products
						for (int i = 0; i < record.length(); i++) {
							JSONObject c = record.getJSONObject(i);

							// Storing each json item in variable
							String id = c.getString(TAG_UID);
							String name = c.getString(TAG_AC);
							String time = c.getString(TAG_DATA);

							// creating new HashMap
							HashMap<String, String> map = new HashMap<String, String>();

							// adding each child node to HashMap key => value
							map.put(TAG_UID, id);
							map.put(TAG_AC, name);
							map.put(TAG_DATA,time);

							// adding HashList to ArrayList
							recordList.add(map);
						}
					} else {
			
					}
				} catch (JSONException e) {
					e.printStackTrace();
				}

				return null;
			}


			protected void onPostExecute(String file_url) {
				// dismiss the dialog after getting all products
		
				// updating UI from Background Thread
				runOnUiThread(new Runnable() {
					public void run() {
					
						ListAdapter adapter = new SimpleAdapter(
								ReocrdActivity.this, recordList,
								R.layout.list_item, new String[] { TAG_UID,
										TAG_AC, TAG_DATA},
								new int[] { R.id.pid, R.id.name, R.id.time });
						// updating listview
						setListAdapter(adapter);
					}
				});

	

		}}
		
}
