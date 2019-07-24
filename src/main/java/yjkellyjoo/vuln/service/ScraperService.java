package yjkellyjoo.vuln.service;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;

import javax.annotation.Resource;

import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

import yjkellyjoo.runtime.util.StringUtil;
import yjkellyjoo.vuln.dao.CveDao;
import yjkellyjoo.vuln.dao.ProductDao;
import yjkellyjoo.vuln.dao.VulnLibraryDao;
import yjkellyjoo.vuln.model.CveVo;
import yjkellyjoo.vuln.model.ProductVo;
import yjkellyjoo.vuln.model.VulnLibraryInfo;
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
	
	@Resource(name="yjkellyjoo.vuln.dao.ProductDao")
	private ProductDao productDao;
	
	@Resource(name="yjkellyjoo.vuln.dao.CveDao")
	private CveDao cveDao;
	
	/**
	 * VULN_LIBRARY 정보 조회
	 */
	public void perform() {
		log.debug("performing... ");
		
		List<VulnLibraryVo> vulnLibList = vulnLibraryDao.selectAllVulnLibraryList();
		
		for (VulnLibraryVo vulnLibraryVo : vulnLibList) {
			log.debug("VULN_LIB: {} ", vulnLibraryVo.getRefId() );
			this.manageDescription(vulnLibraryVo);
		}
	}

	/**
	 * CVE 정보에서 description 부분 training data
	 * @param vulnLib
	 */
	private void manageDescription(VulnLibraryVo vulnLib) {
		// TB_VULN_LIBRARY에 row가 저장은 되어있는데 정보가 빈 경우..
		if (vulnLib.getVulnLibraryInfos().size() == 0) {
			return;
		}
		
		CveVo cve = cveDao.selectCve(vulnLib.getRefId());

		VulnLibraryInfo vulnLibInfo = vulnLib.getVulnLibraryInfos().get(0);
		
		String description = cve.getDescriptionString();
		String vendor, product;

		ProductVo productVo = productDao.selectProduct(vulnLibInfo.getLangauage(), vulnLibInfo.getRepository(), vulnLibInfo.getProductKey());
		log.debug("productVo: {}, {}, {} ", vulnLibInfo.getLangauage(),  vulnLibInfo.getRepository(),  vulnLibInfo.getProductKey());

		if (vulnLibInfo.getLangauage().compareTo("javascript") == 0) {
			try {
				String tmp[] = productVo.getName().split("/");
				if (tmp.length == 2) {
					vendor = tmp[0].substring(1);
					description = description.replaceAll("(?i)"+vendor, "<START:vendor> " + vendor + " <END>");
					product = tmp[1];
					description = description.replaceAll("(?i)"+product, "<START:product> " + product + " <END>");
				}
				else {
					product = tmp[0];
					description = description.replaceAll("(?i)"+product, "<START:product> " + product + " <END>");
				}
			} catch (NullPointerException e){
				File error = new File("Null_error.txt");
				try {
				FileUtils.writeStringToFile(error, vulnLib.getRefId() +", "+ vulnLibInfo.getLangauage() +", "+ vulnLibInfo.getRepository() +", "+ vulnLibInfo.getProductKey()+"\n", StandardCharsets.UTF_8, true);
				} catch(IOException ex) {
					ex.printStackTrace();
				}
				e.printStackTrace();
			}
		}
		else {
			String tmp[] = productVo.getProductKey().split(":");
			if (tmp.length == 2) {
				vendor = StringUtil.getStringName(tmp[0]);
				description = description.replaceAll("(?i)"+vendor, "<START:vendor> " + vendor + " <END>");
				product = StringUtil.getStringName(tmp[1]);
				description = description.replaceAll("(?i)"+product, "<START:product> " + product + " <END>");
			}
			else {
				product = StringUtil.getStringName(tmp[0]);
				description = description.replaceAll("(?i)"+product, "<START:product> " + product + " <END>");
			}
		}
		
		File trainData = new File("vendor-product.train");

		try {
//			FileUtils.writeStringToFile(trainData, vulnLib.getRefId()+": "+description+"\n", StandardCharsets.UTF_8, true);
			FileUtils.writeStringToFile(trainData, description+"\n", StandardCharsets.UTF_8, true);
		} catch (IOException e) {
			e.printStackTrace();
		}		

	}

}
