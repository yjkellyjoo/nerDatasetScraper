/**
 * Copyright (c) 2018 IoTcube, Inc.
 * All right reserved.
 *
 * This software is the confidential and proprietary information of IoTcube, Inc. 
 * You shall not disclose such Confidential Information and
 * shall use it only in accordance with the terms of the license agreement
 * you entered into with IoTcube, Inc.
*/

package yjkellyjoo.runtime.mybatis;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import yjkellyjoo.vuln.model.VulnLibraryInfo;

/**
 * 
 * @author 	hyeonggookim
 * @since 	2019. 2. 25.
 */

public class JsonListVulnLibraryInfoTypeHandler extends BaseTypeHandler<List<VulnLibraryInfo>> {


	@Override
	public void setNonNullParameter(PreparedStatement ps, int i, List<VulnLibraryInfo> parameter, JdbcType jdbcType)
			throws SQLException {
		
		ps.setString(i, convert(parameter));
	}


	@Override
	public List<VulnLibraryInfo> getNullableResult(ResultSet rs, String columnName) throws SQLException {
		
		return convert(rs.getString(columnName));
	}
	
	@Override
	public List<VulnLibraryInfo> getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
		
		return convert(rs.getString(columnIndex));
	}

	@Override
	public List<VulnLibraryInfo> getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
		
		return convert(cs.getString(columnIndex));
	}

	private String convert(List<VulnLibraryInfo> parameter) {
    	String jsonStr = null;

    	try {
    		jsonStr = new ObjectMapper().writeValueAsString(parameter);
    	} catch (JsonProcessingException e) {
    		e.printStackTrace();
    	}

    	return jsonStr;
    }

    private List<VulnLibraryInfo> convert(String s) {
    	List<VulnLibraryInfo> result = null;
    	
    	if (!StringUtils.isEmpty(s)) {
        	try {
        		result = new ObjectMapper().readValue(s, new TypeReference<List<VulnLibraryInfo>>() {});
    		} catch (Exception e) {
    			e.printStackTrace();
    		}
    	}
    	
    	return result;
    }
}
