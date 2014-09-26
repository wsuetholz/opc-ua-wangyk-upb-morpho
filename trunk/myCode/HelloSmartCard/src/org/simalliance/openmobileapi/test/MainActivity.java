package org.simalliance.openmobileapi.test;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONException;
import org.json.JSONObject;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Intent;
import android.graphics.Color;
import android.os.AsyncTask;
import android.os.Bundle;
import android.text.Html;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.method.ScrollingMovementMethod;
import android.text.style.ForegroundColorSpan;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup.LayoutParams;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.TextView.BufferType;
import android.widget.Toast;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Spinner;
import android.widget.AdapterView.OnItemSelectedListener;

import org.simalliance.openmobileapi.*;


public class MainActivity extends Activity implements SEService.CallBack, OnItemSelectedListener {

	final String LOG_TAG = "Smart Home";
	
	/** Open Mobile API service. */
	SEService scservice = null;
	String cardreader = "";
	Channel logicalChannel = null;
	TextView tv;
	
	private Spinner deviceSpinner ;
	private Spinner functionSpinner ;
	
	private ArrayAdapter<String> deviceAdapter;
	private ArrayAdapter<String> functionAdapter;
	
	private TextView channel;
	private TextView pkValue;
	private TextView welcome;
	
	private Button openChannel;
	private Button reset;
	private Button getPK;
	private Button send;
	private Button record;
	
	private EditText paramInput;
	
	UiDesign myUI = new UiDesign();
	CmdTranslate cmd = new CmdTranslate();
	
	// Progress Dialog
	static JSONParser jsonParser = new JSONParser();	
	private static final String url_sensor_detials = "http://10.0.2.2:8080/query_sensor.php";
	private static final String url_update_sensor =  "http://10.133.68.27/update_sensor.php";
	private static final String url_update_record =  "http://10.133.68.27/update_record.php";
	private static final String url_read_sensor =  "http://10.133.68.27/read_sensor.php";
	private static final String url_update_door =  "http://10.133.68.27/update_door.php";
	private static final String url_read_record ="http://10.133.68.27/read_record.php";
	
	private static final String TAG_SUCCESS = "success";
	private static final String TAG_SENSOR = "TempSensor";
	private static final String TAG_CURRENT_VALUE = "CurrentValue";
	private static final String TAG_NAME = "Name";
	private static final String TAG_USER = "User";
	private static final String TAG_SUB = "Subscription";
	private static final String TAG_ACT = "activity";
	private static final String TAG_DATE = "date";
	private static final String TAG_PRE = "product";
	private static final String TAG_ID = "user_id";
	private static final String TAG_AR = "access_right";
	private static final String TAG_MSG = "message";
	
	private static final String failedFlag = " <font color='red'>Failed</font>\n";
	private static final String sucessFlag = " <font color='green'>Sucess</font>\n";
	
	@Override
	public void onCreate(Bundle savedInstanceState) {

		super.onCreate(savedInstanceState);
		// do layout and UI stuff
		setContentView(R.layout.main);
		
		// Buttons
		openChannel = (Button) findViewById(R.id.widget36);
		reset = (Button) findViewById(R.id.widget36_copy_1);
		getPK = (Button) findViewById(R.id.widget36_copy);
		send = (Button) findViewById(R.id.widget43_b);
		record = (Button)findViewById(R.id.Button01);
		
		//Textviews
		
		channel = (TextView) findViewById(R.id.textView1);
		pkValue = (TextView) findViewById(R.id.textView2);
		welcome = (TextView) findViewById(R.id.widget46);
		//welcome.setSingleLine(false);
		
		//Spinners
		
		deviceSpinner = (Spinner)findViewById(R.id.widget43);
		functionSpinner = (Spinner)findViewById(R.id.widget43_copy);
		
		paramInput = (EditText)findViewById(R.id.Parameter);
				
		scservice = new SEService(this, this);
		
		openChannel.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
				try {
					performSelectOpt (scservice);
				} catch (Exception e) {
					Log.e(LOG_TAG, "Error occured:", e);
					return;
				}
			}
		});
		
		record.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
				try {
	
				Intent intent = new Intent();           			  	
				intent.setClass(MainActivity.this, ReocrdActivity.class);  
				startActivity(intent);  
				finish(); 
			
		
				}
           		catch (Exception e) {
					Log.e(LOG_TAG, "Error occured:", e);
					return;
				}
			}
		});
		
		reset.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
				try {
				paramInput.setText(null);
				} catch (Exception e) {
					Log.e(LOG_TAG, "Error occured:", e);
					return;
				}
			}
		});
		
		getPK.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
				try {
					performGetPk(scservice);
				} catch (Exception e) {
					Log.e(LOG_TAG, "Error occured:", e);
					return;
				}
			}
		});
		send.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
				try {
					sendOperation(scservice);
				} catch (Exception e) {
					Log.e(LOG_TAG, "Error occured:", e);
					return;
				}
			}
		});

		
		deviceSpinner.setOnItemSelectedListener(this);
		
		
		
		channel.setText(myUI.getStyle("CLOSED", "RED"));
		pkValue.setText(myUI.getStyle("NONE PK"
				+ "", "RED"));
		paramInput.setText(null);
		
	}

	public void onItemSelected(AdapterView<?> arg0, View arg1, int arg2,
            long arg3) {
		
        String sp1= String.valueOf(deviceSpinner.getSelectedItem());
        Toast.makeText(this, sp1, Toast.LENGTH_SHORT).show();
        if(sp1.contentEquals("TempSensor")) {
            List<String> list = new ArrayList<String>();
            list.add("GetValue");
            list.add("SetSub");
            list.add("GetRecord");
            ArrayAdapter<String> dataAdapter = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, list);
            dataAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            dataAdapter.notifyDataSetChanged();
            functionSpinner.setAdapter(dataAdapter);
        }
        if(sp1.contentEquals("DoorLock")) {
            List<String> list = new ArrayList<String>();
            list.add("Open");
            list.add("GrantAccess");
            list.add("GetRecord");
            ArrayAdapter<String> dataAdapter2 = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, list);
            dataAdapter2.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            dataAdapter2.notifyDataSetChanged();
            functionSpinner.setAdapter(dataAdapter2);
        }
        if(sp1.contentEquals("CafeMaker")) {
            List<String> list = new ArrayList<String>();
            list.add("MakeCafe");
            list.add("AddWater");
            list.add("AddCafe");
            ArrayAdapter<String> dataAdapter2 = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, list);
            dataAdapter2.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            dataAdapter2.notifyDataSetChanged();
            functionSpinner.setAdapter(dataAdapter2);
        }
         
    }
	//put SEND
	
	void sendOperation(SEService service) throws UnsupportedEncodingException {
		String command = "";

			
		String param1 =String.valueOf(deviceSpinner.getSelectedItem());
		String param2 =String.valueOf(functionSpinner.getSelectedItem());
		
		String paramByte = cmd.getParam(param1);
		String cmdByte = cmd.getCmd(cmd.getCmdTlv(param2, paramInput.getText().toString() ));
		
		command = "A024" + paramByte + cmd.hexStringToByte(cmdByte.length()/2)+ cmdByte;
		/*
		if (param2.equals("SetSub") || param2.equals("GrantAccess"))
		{
			welcome.append (param1 +" " + param2 + " "+ paramInput.getText().toString() +"\n" );
			welcome.append(command +"\n"); 
		}
		else
		{
			welcome.append (param1 +" " + param2 + "\n" );
			welcome.append(command +"\n"); 
		}
		*/
		if (param1.equals("TempSensor") && param2.equals("SetSub"))
		{	
			String input = param1 +" " + param2 + " "+ paramInput.getText().toString() +"\n" ;
			welcome.append (myUI.getStyle(input, 17, 20, "GREEN"));
			SensorUpdate up = new SensorUpdate();
			up.execute();
			RecordUpdate rUp = new RecordUpdate();
			rUp.execute();
		}
		if (param1.equals("TempSensor") && param2.equals("GetValue"))
		{	
			welcome.append (param1 +" " + param2 + "\n" );
			ReadSensor read = new ReadSensor();
			read.execute();
		}
		if (param1.equals("DoorLock") && param2.equals("Open"))
		{	
			welcome.append (param1 +" " + param2 + "\n" );
			DLUpdate dlUp = new DLUpdate();
			dlUp.execute();
		}
		if (param1.equals("DoorLock") && param2.equals("GrantAccess"))
		{	
			welcome.append (param1 +" " + param2 + "\n" );
			DoorUpdate doorUp = new DoorUpdate();
			doorUp.execute();
			DLUpdate dlUp = new DLUpdate();
			dlUp.execute();
		}

		
	}
	
	
	void performSelectOpt(SEService service) {
		try {
			
			Reader[] readers = service.getReaders();
			cardreader = readers[0].getName();

			boolean isPresent = readers[0].isSecureElementPresent();
			Log.d(LOG_TAG, isPresent ? " present\n" : " absent\n");

			Session session = readers[0].openSession();
			
			//01 01 01 01 21 01 01 22
			final byte[] hellosimcard = new byte[] {(byte)0x01,(byte)0x01,(byte)0x01,(byte)0x01,(byte)0x21,(byte)0x01,(byte)0x01,(byte)0x22};
			
			logicalChannel = session.openLogicalChannel(hellosimcard);
			
			//channel.setText(myUI.getStyle("OPEN", "GREEN"));
			
			//welcome.append(Html.fromHtml("<font color='green'>Service Created!</font><br>"));
			
			performOpenOpt(service);
			
		} catch (Exception ex) {
			welcome.append(ex.getMessage()+"\n");
		}
	}
	
	void performOpenOpt(SEService service) {
		try {
			byte[] cmdApdu = new byte[] { (byte) 0xA0, (byte) 0x04, (byte)0x00, (byte)0x00,
					(byte)0x02 };
			byte[] result = logicalChannel.transmit(cmdApdu);
			
					
		Log.d(LOG_TAG, "result length: " + result.length + ". "
				+ byteArrayToHexString(result));

			byte[] helloStr = new byte[result.length];
			System.arraycopy(result, 0, helloStr, 0, result.length);
			Toast.makeText(MainActivity.this, byteArrayToHexString(result),
					Toast.LENGTH_SHORT).show();
		if (byteArrayToHexString(result).equals("9000"))
		{
	    channel.setText(myUI.getStyle("OPEN", "GREEN"));	
		}
		else
		{
			 channel.setText(myUI.getStyle("FAILED", "RED"));	
			 welcome.append(byteArrayToHexString(result)+"\n");
		}
			
		} catch (Exception ex) {
			welcome.append(ex.getMessage()+"\n");
		}
	}
	
	
	void performSendOpt(SEService service, String cmd) {
		try {
			byte[] cmdApdu = new BigInteger((cmd),16).toByteArray();
			welcome.append(byteArrayToHexString(cmdApdu)+"\n");
		} catch (Exception ex) {
			welcome.append(ex.getMessage()+"\n");
		}
	}
	void performGetPk(SEService service) {
		try {
			String fialed = " <font color='red'>Failed</font>\n";
			String success = " <font color='green'>Sucess</font>\n";
			String param1 =String.valueOf(deviceSpinner.getSelectedItem());
			String paramByte = cmd.getParam(param1);
			byte[] cmdApdu = Hex.decode ("A006" + paramByte+"02");
			byte[] result = logicalChannel.transmit(cmdApdu);		
			
			
			//welcome.append(byteArrayToHexString(cmdApdu)+"\n");
			if (byteArrayToHexString(result).endsWith("9000"))
			{	
				welcome.append(myUI.getStyle("Require PubKey Success \n",14,22, "GREEN"));
				pkValue.setText(myUI.getStyle(byteArrayToHexString(result).replaceAll("9000","")
						, "GREEN"));
			}
			else
			{	welcome.append(myUI.getStyle("Require PubKey Failed \n",14,21, "RED"));
				pkValue.setText(myUI.getStyle("Failed"
						, "RED"));
			}
		} catch (Exception ex) {
			welcome.append(ex.getMessage()+"\n");
		}
	}
	void performsOperations(SEService service) {
		try {
			Reader[] readers = service.getReaders();
			cardreader = readers[0].getName();

			boolean isPresent = readers[0].isSecureElementPresent();
			Log.d(LOG_TAG, isPresent ? " present\n" : " absent\n");

			Session session = readers[0].openSession();
			
			tv.setText("1: session opened." );
			//0101010121S
			final byte[] hellosimcard = new byte[] {0x01,0x01,0x01,0x01,0x21};
			
			logicalChannel = session.openLogicalChannel(hellosimcard);
			tv.setText("1: channel opened.");
		} catch (Exception ex) {
			tv.setText("1:" + ex.getMessage());
		}
	}
	

	void performsOperations2(SEService service) {
		try {
			byte[] cmdApdu = new byte[] { (byte) 0xA0, (byte) 0x07, 0x00, 0x00,
					0x01 };
			byte[] result = logicalChannel.transmit(cmdApdu);
			
//			cmdApdu = new byte[] { (byte) 0xA0, (byte) 0xC0, 0x00, 0x00, 0x14 };			
//			result = logicalChannel.transmit(cmdApdu);
					
		Log.d(LOG_TAG, "result length: " + result.length + ". "
				+ byteArrayToHexString(result));

			byte[] helloStr = new byte[result.length];
			System.arraycopy(result, 0, helloStr, 0, result.length);
			Toast.makeText(MainActivity.this, byteArrayToHexString(result),
					Toast.LENGTH_SHORT).show();
		} catch (Exception ex) {
			tv.setText("2:" + ex.getMessage());
		}
	}

	@Override
	protected void onDestroy() {
		if (scservice != null && scservice.isConnected()) {
			scservice.shutdown();
		}
		super.onDestroy();
	}

	public void serviceConnected(SEService service) {
		Log.i(LOG_TAG, "entry: seviceConnected()");
	}

	private static String byteArrayToHexString(byte in[]) {

		byte ch = 0x00;

		int i = 0;

		if (in == null || in.length <= 0)
			return null;

		String pseudo[] = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
				"A", "B", "C", "D", "E", "F" };

		StringBuffer out = new StringBuffer(in.length * 2);

		while (i < in.length) {
			ch = (byte) (in[i] & 0xF0); // Strip off high nibble

			ch = (byte) (ch >>> 4); // shift the bits down

			ch = (byte) (ch & 0x0F); // must do this is high order bit is on!

			out.append(pseudo[(int) ch]); // convert the nibble to a String

			ch = (byte) (in[i] & 0x0F); // Strip off low nibble

			out.append(pseudo[(int) ch]); // convert the nibble to a String

			i++;
		}

		String rslt = new String(out);

		return rslt;

	}
	    public void onNothingSelected(AdapterView<?> arg0) {
	        // TODO Auto-generated method stub      
	    }
	    
	  //////// ============= MYSQL ====================
	    class SensorUpdate extends AsyncTask<String, String, String> {
			protected void onPreExecute() {}
			protected String doInBackground(String... params) {

				runOnUiThread(new Runnable() {
					public void run() {
						// Check for success tag
						int success;
						try {
							// Building Parameters
							String Name = "TempSensor";
							String Subscription = paramInput.getText().toString();
							List<NameValuePair> params = new ArrayList<NameValuePair>();
							params.add(new BasicNameValuePair(TAG_NAME, Name));
							params.add(new BasicNameValuePair(TAG_SUB, Subscription));
							// getting product details by making HTTP request
							// Note that product details url will use GET request
							JSONObject json = jsonParser.makeHttpRequest(
									url_update_sensor, "GET", params);
							// check your log for json response
							Log.d("Smart Home","============sensor_update=================");
							Log.d("Smart Home", json.getString(TAG_MSG));					
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
				});
				return null;
			}	
}
	    class DoorUpdate extends AsyncTask<String, String, String> {
			protected void onPreExecute() {}
			protected String doInBackground(String... params) {
				runOnUiThread(new Runnable() {
					public void run() {
						// Check for success tag
						int success;
						try {
							// Building Parameters
							String Name = paramInput.getText().toString();
							String description = "main_door";
							List<NameValuePair> params = new ArrayList<NameValuePair>();
							params.add(new BasicNameValuePair(TAG_ID, Name));
							params.add(new BasicNameValuePair(TAG_AR, description));
							// getting product details by making HTTP request
							// Note that product details url will use GET request
							JSONObject json = jsonParser.makeHttpRequest(
									url_update_door, "GET", params);

							// check your log for json response
							Log.d("Smart Home","============sensor_update=================");
							Log.d("Smart Home", json.getString(TAG_MSG));					
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
				});
				return null;
			}		
}	    
	    class RecordUpdate extends AsyncTask<String, String, String> {
			protected void onPreExecute() {}	
			protected String doInBackground(String... params) {
				runOnUiThread(new Runnable() {
					public void run() {
						// Check for success tag
						int success;
						try {
							// Building Parameters
							String activity = "set_sensor_subscription_value_" + paramInput.getText().toString() ;
							String date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Calendar.getInstance().getTime());
							List<NameValuePair> params = new ArrayList<NameValuePair>();
							params.add(new BasicNameValuePair(TAG_ACT, activity));
							params.add(new BasicNameValuePair(TAG_DATE, date));
							// getting product details by making HTTP request
							// Note that product details url will use GET request
							JSONObject json = jsonParser.makeHttpRequest(
									url_update_record, "GET", params);
						// check your log for json response
							Log.d("Smart Home","===========record_update=================");
							Log.d("Smart Home", json.getString(TAG_MSG));			
						} 
						catch (Exception e) {
							e.printStackTrace();
						}
					}
				});
				return null;
			}
}
	    class DLUpdate extends AsyncTask<String, String, String> {
	 			protected void onPreExecute() {}
	 			protected String doInBackground(String... params) {
	 				runOnUiThread(new Runnable() {
	 					public void run() {
	 						// Check for success tag
	 						int success;
	 						String activity = "";
	 						try {
	 							// Building Parameters
	 							if (paramInput.getText().toString().isEmpty())
	 							{
	 								 activity = "open_main_door";
	 							}
	 							else
	 							{
	 								 activity = "grant_main_door_access_to_" + paramInput.getText().toString();
	 							}
	 							String date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Calendar.getInstance().getTime());
	 							List<NameValuePair> params = new ArrayList<NameValuePair>();
	 							params.add(new BasicNameValuePair(TAG_ACT, activity));
	 							params.add(new BasicNameValuePair(TAG_DATE, date));
	 							// getting product details by making HTTP request
	 							// Note that product details url will use GET request
	 							JSONObject json = jsonParser.makeHttpRequest(
	 									url_update_record, "GET", params);
	 							if (json.getInt(TAG_SUCCESS) == 1 && !paramInput.getText().toString().isEmpty())
	 							{	
	 								String gaResult = "To " + paramInput.getText().toString() +"\n";
	 								welcome.append(myUI.getStyle(gaResult, 2, 8,"GREEN") );
	 							}
	 						// check your log for json response
	 							Log.d("Smart Home","===========record_update=================");
	 							Log.d("Smart Home", json.getString(TAG_MSG));			
	 						} 
	 						catch (Exception e) {
	 							e.printStackTrace();
	 						}
	 					}
	 				});
	 				return null;
	 			}
	 }

	    class ReadSensor extends AsyncTask<String, String, String> {
			protected void onPreExecute() {}
			protected String doInBackground(String... params) {
				runOnUiThread(new Runnable() {
					public void run() {
						// Check for success tag
						int success;
						try {
							// Building Parameters
							List<NameValuePair> params = new ArrayList<NameValuePair>();
							params.add(new BasicNameValuePair(TAG_NAME, "TempSensor"));
							// getting product details by making HTTP request
							// Note that product details url will use GET request
							JSONObject json = jsonParser.makeHttpRequest(
									url_read_sensor, "GET", params);
						// check your log for json response
							Log.d("Smart Home","===========sensor value=================");
							Log.d("Smart Home",json.toString());
							String result = "CurrentValue " + json.getString(TAG_SENSOR) + "\n";
							welcome.append(myUI.getStyle(result, 12, 15, "GREEN") );			
						} 
						catch (Exception e) {
							e.printStackTrace();
						}
					}
				});
				return null;
			}
}


	    class ReadRecord extends AsyncTask<String, String, String> {
			protected void onPreExecute() {}
			protected String doInBackground(String... params) {
				runOnUiThread(new Runnable() {
					public void run() {
						// Check for success tag
						try {
													
			
							// Building Parameters
							List<NameValuePair> params = new ArrayList<NameValuePair>();
							params.add(new BasicNameValuePair("tst", "tst"));
							// getting product details by making HTTP request
							// Note that product details url will use GET request
							JSONObject json = jsonParser.makeHttpRequest(
									url_read_record, "GET", params);
						// check your log for json response
							Log.d("Smart Home","===========sensor value=================");
							Log.d("Smart Home",json.toString());
			
							Log.d("Smart Home","i was pressed!!!");
						} 
						catch (Exception e) {
							e.printStackTrace();
						}
					}
				});
				return null;
			}
}






}