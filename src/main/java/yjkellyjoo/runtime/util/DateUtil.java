package yjkellyjoo.runtime.util;

import java.sql.Timestamp;
import java.util.Date;

import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;

public class DateUtil {

	public static final String FULL_DATE_TIME_SEC = "yyyy-MM-dd HH:mm:ss";
	public static final String FULL_DATE = "yyyy-MM-dd";
	public static final String FULLDATETIMESEC = "yyyyMMddHHmmss";

	public static String convertLongToLocalTime(long sec, String pattern) {

//		return new DateTime(sec).withZone(DateTimeZone.forID("Asia/Seoul")).toString(pattern);

		return DateTimeFormat.forPattern(pattern).withZone(DateTimeZone.forID("Asia/Seoul")).print(sec);
	}

	public static Timestamp convertDateToTimestamp(Date date) {

		return convertLongToTimestamp(date.getTime());
	}

	public static Timestamp convertLongToTimestamp(Long sec) {

		return new Timestamp(sec);
	}

	public static String convertTimestampToLocalTime(Timestamp timestamp, String pattern) {

		if (timestamp == null) {
			return "";
		}

		return convertLongToLocalTime(timestamp.getTime(), pattern);
	}

	public static boolean isSameTime(long sec1, long sec2) {
		String date1 = convertLongToLocalTime(sec1, FULL_DATE_TIME_SEC);
		String date2 = convertLongToLocalTime(sec2, FULL_DATE_TIME_SEC);

		return date1.equals(date2);
	}

	public static String now(String pattern) {
//		SimpleDateFormat formatter = new SimpleDateFormat(pattern);
//		return formatter.format(new Date());

		return DateTimeFormat.forPattern(pattern).withZoneUTC().print(new Date().getTime());
	}

	public static String now() {
		return now(FULLDATETIMESEC);
	}

	public static Timestamp nowTimestamp() {

		Date date = new Date();
		return new Timestamp(date.getTime());
	}

	public static void main(String args[]) {

		System.out.println(now());
	}
}
