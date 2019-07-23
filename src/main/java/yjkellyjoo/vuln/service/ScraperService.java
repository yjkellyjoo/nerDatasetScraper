package yjkellyjoo.vuln.service;

import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;
import yjkellyjoo.vuln.dao.VulnLibraryDao;
import yjkellyjoo.vuln.model.VulnLibraryVo;

/**
 * 
 * @author 	yjkellyjoo
 * @since	2019. 07. 23.
 */
@Slf4j
@Service("yjkellyjoo.vuln.service.ScraperService")
public class ScraperService {
	
	@Resource(name="yjkellyjoo.vuln.dao.VulnLibraryDao")
	private VulnLibraryDao vulnLibraryDao;
	
	/**
	 * VULN_LIBRARY 정보 조회
	 */
	public void perform() {
		log.info("performing... ");
		
		List<VulnLibraryVo> vulnLibList = vulnLibraryDao.selectAllVulnLibraryList();
		
		for (VulnLibraryVo vulnLibraryVo : vulnLibList) {
			this.manageDescription(vulnLibraryVo);
		}
	}

	
	private void manageDescription(VulnLibraryVo vulnLib) {
		
	}

}
