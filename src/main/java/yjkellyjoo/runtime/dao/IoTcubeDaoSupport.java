/**
 * Copyright (c) 2018 IoTcube, Inc.
 * All right reserved.
 *
 * This software is the confidential and proprietary information of IoTcube, Inc. 
 * You shall not disclose such Confidential Information and
 * shall use it only in accordance with the terms of the license agreement
 * you entered into with IoTcube, Inc.
*/

package yjkellyjoo.runtime.dao;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;

import lombok.Getter;

/**
 * Dao 지원 클래스
 * @author 	hyeonggookim
 * @since 	2018. 11. 27.
 */
@Getter
public abstract class IoTcubeDaoSupport {

	@Autowired
	private SqlSessionTemplate sqlSession;

}
