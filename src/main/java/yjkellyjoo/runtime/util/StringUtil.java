/**
 * Copyright (c) 2018 IoTcube, Inc.
 * All right reserved.
 *
 * This software is the confidential and proprietary information of IoTcube, Inc.
 * You shall not disclose such Confidential Information and
 * shall use it only in accordance with the terms of the license agreement
 * you entered into with IoTcube, Inc.
*/

package yjkellyjoo.runtime.util;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

import lombok.extern.slf4j.Slf4j;

/**
 * 문자열 처리
 * @author 	hyeonggookim
 * @since 	2019. 1. 3.
 */
@Slf4j
public class StringUtil {

	/**
	 * url에서 파일명 추출
	 * @param url
	 * @return
	 */
	public static String getFileNameFromUrl(String url) {

		if (isNull(url) || url.indexOf("/") < 0 || url.endsWith("/")){
			return null;
		}

		return url.substring(url.lastIndexOf("/") + 1);
	}

	/**
	 * 문자열이 비었는지 확인
	 * @param str
	 * @return
	 */
	public static boolean isNull(String str) {
		if (str == null || str.trim().length() < 1){
			return true;
		}
		return false;
	}

	/**
	 * object == null 일시 null 반환. 이외의 경우 String 문자열 반환
	 * @param object
	 * @return String
	 */
	public static String stringValueOf(Object object) {
    	return object == null ? null : String.valueOf(object);
    }

    /**
     * items 를 seperator로 구분하는 String 을 반환
     * ex) itmes = ["A","B"], seperator = ":" -> "A:B"
     * @param items
     * @param seperator
     * @return
     */
    public static String join(Iterable<?> items, String seperator) {
        Iterator<?> iter = items.iterator();
        if (!iter.hasNext()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        builder.append(iter.next());
        while (iter.hasNext()) {
            builder.append(seperator).append(iter.next());
        }

        return builder.toString();
    }

	/**
	 * groupId를 pom url 형태로 변경
	 * @param groupId
	 * @return
	 */
	public static String convertGroupIdToUrlPath(String groupId) {

		return groupId.replaceAll("\\.", "/");
	}

	/**
	 * productKey 생성
	 * @param groupId
	 * @param artifactId
	 * @return
	 */
	public static String getProductKey(String groupId, String artifactId) {

		return groupId.toLowerCase() + ":" + artifactId.toLowerCase();
	}

	public static String getVersionKey(String groupId, String artifactId, String version) {

		return groupId.toLowerCase() + ":" + artifactId.toLowerCase() + ":" + version.toLowerCase();
	}

	public static void main(String args[]) {

		String url = "http://test.com/test.xml";
		log.info("getFileNameFromUrl : {}, {}", url, getFileNameFromUrl(url));

		Map<String, String> properties = new HashMap<String, String>();
		properties.put("project.version", "1.3.3");
		properties.put("project32123.version", "1.3.33333");

		String vul = "./vul/xserver/CVE-2017-12183_0.0_CWE-000_61502107a30d64f991784648c3228ebc6694a032_region.c_19_OLD.vul";
		log.debug(vul.substring(vul.lastIndexOf("xserver") + "xserver".length() + 1));
		log.debug(checkVariables("33333-${project.version}-${project32123.version}", properties));
	}


	/**
	 * Method which converts dateString extracted from the nvd files into Timestamp data format.
	 * @param A String with Date information of format 'yyyy-MM-dd', 'yyyy-MM-ddThh:mmZ', 'yyyy-MM-ddThh:mm:ss.mmmZ', or 'yyyy-MM-ddThh:mm:ss.mmm-HH:MM'
	 * @return Timestamp of format 'yyyy-MM-dd hh:mm:ss.000000'
	 */
	public static Timestamp convertStringToTimestamp(String dateString) {
		Timestamp timestamp = null;
		int len = dateString.length();

		// for CWE, CAPEC of format 'yyyy-MM-dd'
		if (len <= 10) {
	    	timestamp = Timestamp.valueOf(dateString + " 00:00:00.000000");
		}
		// for CVE of format 'yyyy-MM-ddThh:mmZ'
		else if (len <= 17) {
			dateString = dateString.replace('T', ' ');
			dateString = dateString.substring(0,16).concat(":00.000000");
			timestamp = Timestamp.valueOf(dateString);
		}
		// for CPE of format 'yyyy-MM-ddThh:mm:ss.mmmZ', or 'yyyy-MM-ddThh:mm:ss.mmm-HH:MM'
		else {
			dateString = dateString.replace('T', ' ');
			dateString = dateString.substring(0,19).concat(".000000");
			timestamp = Timestamp.valueOf(dateString);
		}
		return timestamp;
	}

	public static String checkVariables(String val, Map<String, String> properties){
    	// 중간에 시작하는 경우도 있어서 startsWith -> contains로 변경

        try {
        	String[] keys = val.split("\\$\\{");
        	StringBuffer value = new StringBuffer();
        	for (int i=0; i<keys.length; i++) {
        		if (!keys[i].contains("}")) {
        			value.append(keys[i]);
        		} else if (keys[i].endsWith("}")) {
        			keys[i] = keys[i].replaceAll(Pattern.quote("}"), "").toLowerCase();
//        			value.append(properties.get(keys[i]));
        			//System.out.println("1" + keys[i]);
        			value.append(getPropertyValue(keys[i], properties));
        		} else {
        			int pos = keys[i].indexOf("}");
        			String _key = keys[i].substring(0,  pos).toLowerCase();
        			//value.append(properties.get(_key));
        			//System.out.println("2" + _key);
        			value.append(getPropertyValue(_key, properties));
        			value.append(keys[i].substring(pos+1));
        		}
        	}
        	return value.toString();
        } catch (Exception e) {
        	e.printStackTrace();
        	log.error("checkVariable Error : {}", val);
        	return val;
        }
	}

	private static String getPropertyValue(String key, Map<String, String> properties) {
    	String propertyValue = properties.get(key.toLowerCase());
    	if (propertyValue != null && !propertyValue.trim().equals("")) {
          return propertyValue;
    	} else {
          return "${" + key + "}";
    	}
    }
}
