/**
 * Copyright (c) 2018 IoTcube, Inc.
 * All right reserved.
 *
 * This software is the confidential and proprietary information of IoTcube, Inc.
 * You shall not disclose such Confidential Information and
 * shall use it only in accordance with the terms of the license agreement
 * you entered into with IoTcube, Inc.
*/

package yjkellyjoo.vuln.dao;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Repository;

import yjkellyjoo.vuln.model.CveVo;
import yjkellyjoo.runtime.dao.IoTcubeDaoSupport;
import yjkellyjoo.vuln.model.CveSearchOption;

/**
 *
 * @author 	hyeonggookim
 * @since 	2019. 2. 20.
 */
@Repository("yjkellyjoo.vuln.dao.CveDao")
public class CveDao extends IoTcubeDaoSupport {

	/**
	 * CVE 단건 조회
	 * @param cveId
	 * @return
	 */
	public CveVo selectCve(String cveId) {

		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("cveId", cveId);

		return getSqlSession().selectOne("yjkellyjoo.vuln.dao.CveDao.selectCve", paramMap);
	}

	/**
	 * 페이징 처리해서 CVE 목록 조회
	 * @param searchOption
	 * @return
	 */
	public List<CveVo> selectCveListPaging(CveSearchOption searchOption) {

		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("param", searchOption);

		return getSqlSession().selectList("yjkellyjoo.vuln.dao.CveDao.selectCveListPaging", paramMap);
	}

	/**
	 * CVE 전체 갯수 조회
	 * @param searchOption
	 * @return
	 */
	public int selectTotalCveCount(CveSearchOption searchOption) {

		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("param", searchOption);

		return getSqlSession().selectOne("yjkellyjoo.vuln.dao.CveDao.selectTotalCveCount", paramMap);
	}
}
