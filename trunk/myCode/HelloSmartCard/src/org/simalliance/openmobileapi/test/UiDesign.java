package org.simalliance.openmobileapi.test;

import android.graphics.Color;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;

public class UiDesign {
	

	public SpannableStringBuilder getStyle(String text, int begin, int end, String Farbe)
	
	{
		
			SpannableStringBuilder style = new SpannableStringBuilder(text);
			if( Farbe == "RED"){
			style.setSpan(new ForegroundColorSpan(Color.RED),begin,end,Spannable.SPAN_EXCLUSIVE_INCLUSIVE);
			}
			if (Farbe == "GREEN"){
				
				style.setSpan(new ForegroundColorSpan(Color.GREEN),begin,end,Spannable.SPAN_EXCLUSIVE_INCLUSIVE);
			}
			return style;
	
	}
	
	public SpannableStringBuilder getStyle(String text, int begin, String Farbe)
	
	{
			int end = text.length();
			SpannableStringBuilder style = new SpannableStringBuilder(text);
			if( Farbe == "RED"){
			style.setSpan(new ForegroundColorSpan(Color.RED),begin,end,Spannable.SPAN_EXCLUSIVE_INCLUSIVE);
			}
			if (Farbe == "GREEN"){
				
				style.setSpan(new ForegroundColorSpan(Color.GREEN),begin,end,Spannable.SPAN_EXCLUSIVE_INCLUSIVE);
			}
			return style;
	
	}
	
	public SpannableStringBuilder getStyle(String text,String Farbe)
	
	{
			int end = text.length();
			SpannableStringBuilder style = new SpannableStringBuilder(text);
			if( Farbe == "RED"){
				
			style.setSpan(new ForegroundColorSpan(Color.RED),0,end,Spannable.SPAN_EXCLUSIVE_INCLUSIVE);
			
			}
			if (Farbe == "GREEN"){
				style.setSpan(new ForegroundColorSpan(Color.GREEN),0,end,Spannable.SPAN_EXCLUSIVE_INCLUSIVE);
				}
			return style;
	
	}
}
