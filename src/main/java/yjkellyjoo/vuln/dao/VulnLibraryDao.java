package yjkellyjoo.vuln.dao;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Repository;

import yjkellyjoo.runtime.dao.IoTcubeDaoSupport;
import yjkellyjoo.vuln.model.VulnLibraryVo;

/**
 *
 * @author 	hyeonggookim
 * @since 	2019. 2. 25.
 */
@Repository("yjkellyjoo.vuln.dao.VulnLibraryDao")
public class VulnLibraryDao extends IoTcubeDaoSupport {


	/**
	 * 라이브러리 취약점 등록한 것 조회
	 * @param vulnSourceCd
	 * @param refId
	 * @return
	 */
	public VulnLibraryVo selectVulnLibrary(String vulnSourceCd, String refId) {

		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("vulnSourceCd", vulnSourceCd);
		paramMap.put("refId", refId);

		return getSqlSession().selectOne("yjkellyjoo.vuln.dao.VulnLibraryDao.selectVulnLibrary", paramMap);
	}

	/**
	 * 모든 취약점 목록 조회
	 * @return
	 */
	public List<VulnLibraryVo> selectAllVulnLibraryList() {

		return getSqlSession().selectList("yjkellyjoo.vuln.dao.VulnLibraryDao.selectAllVulnLibraryList");
	}

	/**
	 * 라이브러리 취약점 등록
	 * @param vo
	 * @return
	 */
	public int insertVulnLibrary(VulnLibraryVo vo) {

		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("lib", vo);

		return getSqlSession().insert("yjkellyjoo.vuln.dao.VulnLibraryDao.insertVulnLibrary", paramMap);
	}

	/**
	 * 취약점 정보 수정
	 * @param vo
	 * @return
	 */
	public int updateVulnLibrary(VulnLibraryVo vo) {

		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("lib", vo);

		return getSqlSession().update("yjkellyjoo.vuln.dao.VulnLibraryDao.updateVulnLibrary", paramMap);
	}
}
