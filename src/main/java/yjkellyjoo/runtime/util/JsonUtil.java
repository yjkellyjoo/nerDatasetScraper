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

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

/**
 *
 * @author 	hyeonggookim
 * @since 	2019. 2. 12.
 */
@Slf4j
public class JsonUtil {

	/**
	 * Json을 Map 형태로 변환
	 * @param json
	 * @return
	 */
	public static LinkedHashMap<String, Object> convertJsonToMap(String json) {
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			TypeReference<Map<String, Object>> typeReference = new TypeReference<Map<String, Object>>() {
			};
			return objectMapper.readValue(json, typeReference);
		} catch (Exception e) {
			log.info("Error converting Json to Map .");
			return new LinkedHashMap<String, Object>();
		}

//		return null;
	}

	/**
	 * Map 형태를 Json으로 변환
	 * @param map
	 * @return
	 */
	public static String convertMapToJson(Map<String, Object> map) {
		try {
			if (map == null) {
				return null;
			}
			return new ObjectMapper().writeValueAsString(map);
		} catch (JsonProcessingException e) {
			log.debug("Error converting Map to JSon .");
		}
		return null;
	}

	public static String convertObjectMapToJson(Map<Object, Object> map) {
		try {
			if (map == null) {
				return null;
			}
			return new ObjectMapper().writeValueAsString(map);
		} catch (JsonProcessingException e) {
			log.debug("Error converting Map to JSon .");
		}
		return null;
	}

	/**
	 * Json을 List 형태로 변환
	 * @param json
	 * @return
	 */
	public static <T> List<T> convertJsonToList(String json) {
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			TypeReference<List<T>> typeReference = new TypeReference<List<T>>() {
			};
			return objectMapper.readValue(json, typeReference);
		} catch (IOException e) {
			log.debug("Error converting Json to Map .");
		}

		return null;
	}

	/**
	 * JSON을 LinkedHashMap의 List 형태로 변환
	 * @param json
	 * @return
	 */
	public static List<LinkedHashMap<String, Object>> convertJsonToLinkedHashMapList(String json) {
		ObjectMapper objectMapper = new ObjectMapper();
		if (json == null || "".equals(json)) {
			return null;
		}
		try {
			TypeReference<List<LinkedHashMap<String, Object>>> typeReference = new TypeReference<List<LinkedHashMap<String, Object>>>() {};
			return objectMapper.readValue(json, typeReference);
		} catch (IOException e) {
			e.printStackTrace();
			log.debug("Error converting Json to Map .");
		}

		return null;
	}

	/**
	 * List를 Json 형태로 변환
	 * @param list
	 * @return
	 */
	public static <T> String convertListToJson(List<T> list) {
		try {
			return new ObjectMapper().writeValueAsString(list);
		} catch (JsonProcessingException e) {
			log.debug("Error converting Map to JSon .");
		}
		return null;
	}


	/**
	 * Object를 Json 형태로 변환
	 * @param obj
	 * @return
	 */
	public static String convertObjectToJson(Object obj) {
		return convertMapToJson(converObjectToMap(obj));
	}

	/**
	 * Json을 Object 형태로 변환
	 * @param <T>
	 * @param jsonString
	 * @param objClass
	 * @return
	 */
	public static <T> T convertJsonToObject(String jsonInString, Class<T> valueType) {
		ObjectMapper mapper = new ObjectMapper();

		try {
			return mapper.readValue(jsonInString, valueType);

		} catch (JsonGenerationException e) {
			log.debug("Error convertJsonToObject .");
			e.printStackTrace();
		} catch (JsonMappingException e) {
			log.debug("Error convertJsonToObject .");
			e.printStackTrace();
		} catch (IOException e) {
			log.debug("Error convertJsonToObject .");
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Object를 Map 형태로 변환
	 * @param obj
	 * @return
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static Map<String, Object> converObjectToMap(Object obj){
        try {
            Field[] fields = obj.getClass().getDeclaredFields();
            Map resultMap = new HashMap();
            for(int i=0; i<=fields.length-1;i++){
                fields[i].setAccessible(true);
                resultMap.put(fields[i].getName(), fields[i].get(obj));
            }
            return resultMap;
        } catch (IllegalArgumentException e) {
            log.debug("Error convert Object to Map ." );
        } catch (IllegalAccessException e) {
        		log.debug("Error convert Object to Map ." );
        }
        return null;
    }

	/**
	 * Map을 Object 형태로 변환
	 * @param map
	 * @param objClass
	 * @return
	 */
	@SuppressWarnings("rawtypes")
	public static Object convertMapToObject(Map map, Object objClass){
        String keyAttribute = null;
        String setMethodString = "set";
        String methodString = null;
        Iterator itr = map.keySet().iterator();
        while(itr.hasNext()){
            keyAttribute = (String) itr.next();
            methodString = setMethodString+keyAttribute.substring(0,1).toUpperCase()+keyAttribute.substring(1);
            try {
                Method[] methods = objClass.getClass().getDeclaredMethods();
                for(int i=0;i<=methods.length-1;i++){
                    if(methodString.equals(methods[i].getName())){
//                        System.out.println("invoke : "+methodString);
                        methods[i].invoke(objClass, map.get(keyAttribute));
                    }
                }
            } catch (SecurityException e) {
            		log.debug("SecurityException convert Map to Object ." );
            } catch (IllegalAccessException e) {
            		log.debug("IllegalAccessException convert Map to Object ." );
            } catch (IllegalArgumentException e) {
            		log.debug("IllegalArgumentException convert Map to Object ." );
            } catch (InvocationTargetException e) {
            		log.debug("InvocationTargetException convert Map to Object ." );
            }
        }
        return objClass;
    }

	/**
	 * Json 형태인지 확인
	 * @param isThisJson
	 * @return
	 */
	public static boolean isJson(String isThisJson) {

		try {
			new ObjectMapper().readValue(isThisJson, Object.class);
		} catch (Exception e) {
			return false;
		}

		return true;
	}


}
