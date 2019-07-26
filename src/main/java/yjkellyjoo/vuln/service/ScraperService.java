package yjkellyjoo.vuln.service;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Resource;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

import opennlp.tools.namefind.NameFinderME;
import opennlp.tools.namefind.NameSample;
import opennlp.tools.namefind.NameSampleDataStream;
import opennlp.tools.namefind.TokenNameFinderFactory;
import opennlp.tools.namefind.TokenNameFinderModel;
import opennlp.tools.util.MarkableFileInputStreamFactory;
import opennlp.tools.util.ObjectStream;
import opennlp.tools.util.PlainTextByLineStream;
import opennlp.tools.util.TrainingParameters;

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
			log.info("VULN_LIB: {} ", vulnLibraryVo.getRefId() );
			this.manageDescription(vulnLibraryVo);
		}
		
		try {
			this.trainModel();
		} catch (IOException e) {
			e.printStackTrace();
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
		
		List<VulnLibraryInfo> vulnLibInfo = new ArrayList<VulnLibraryInfo>();
		for (VulnLibraryInfo vuln : vulnLib.getVulnLibraryInfos()) {
			VulnLibraryInfo tmp = new VulnLibraryInfo();
			tmp.setLangauage(vuln.getLangauage());
			tmp.setRepository(vuln.getRepository());
			tmp.setProductKey(vuln.getProductKey());
//			log.info("productVo: {}, {}, {} ", tmp.getLangauage(), tmp.getRepository(), tmp.getProductKey());

			boolean flag = true;
			for (int i = 0; i < vulnLibInfo.size(); i++) {
				if (vulnLibInfo.get(i).getProductKey().compareTo(tmp.getProductKey()) == 0) {
					flag = false;
				}
			}
			if (flag) {
				vulnLibInfo.add(tmp);
//				log.info("added");
			}
		}
		
		boolean pflag = false, vflag = false;
		String description = cve.getDescriptionString();
		String vendor, product;

		for (int i = 0; i < vulnLibInfo.size(); i++) {
			ProductVo productVo = productDao.selectProduct(vulnLibInfo.get(i).getLangauage(), vulnLibInfo.get(i).getRepository(), vulnLibInfo.get(i).getProductKey());
			log.info("productVo: {}, {}, {} ", vulnLibInfo.get(i).getLangauage(), vulnLibInfo.get(i).getRepository(), vulnLibInfo.get(i).getProductKey());

			if (vulnLibInfo.get(i).getLangauage().compareTo("javascript") == 0) {
				try {
					String tmp[] = productVo.getName().split("/");
					if (tmp.length == 2) {
						vendor = " "+tmp[0].substring(1)+" ";
						product = " "+tmp[1]+" ";
						int index = StringUtils.indexOfIgnoreCase(description, product);
						if (index > -1) {
							product = description.substring(index, index + product.length());
						}
						index = StringUtils.indexOfIgnoreCase(description, vendor);
						if (index > -1) {
							vendor = description.substring(index, index + vendor.length());
						}

						description = description.replaceAll("(?i)"+product, " <START:product>" + product + "<END> ");
						if (description.contains(product)) {
							pflag = true;
						}
						if (vendor.compareTo(product) != 0) {
							description = description.replaceAll("(?i)"+vendor, " <START:vendor>" + vendor + "<END> ");
							vflag = true;
						}
					}
					else {
						product = " "+tmp[0]+" ";
						
						int index = StringUtils.indexOfIgnoreCase(description, product);
						if (index > -1) {
							product = description.substring(index, index + product.length());
						}
						
						description = description.replaceAll("(?i)"+product, " <START:product>" + product + "<END> ");					
						if (description.contains(product)) {
							pflag = true;
						}
					}
				} catch (NullPointerException e){
					File error = new File("Null_error.txt");
					try {
					FileUtils.writeStringToFile(error, vulnLib.getRefId() +", "+ vulnLibInfo.get(i).getLangauage() +", "+ vulnLibInfo.get(i).getRepository() +", "+ vulnLibInfo.get(i).getProductKey()+"\n", StandardCharsets.UTF_8, true);
					} catch(IOException ex) {
						ex.printStackTrace();
					}
					e.printStackTrace();
				}
			}
			else {
				String tmp[] = productVo.getProductKey().split(":");
				if (tmp.length == 2) {
					vendor = " "+StringUtil.getStringName(tmp[0])+" ";
					product = " "+StringUtil.getStringName(tmp[1])+" ";
					
					int index = StringUtils.indexOfIgnoreCase(description, product);
					if (index > -1) {
						product = description.substring(index, index + product.length());
					}
					index = StringUtils.indexOfIgnoreCase(description, vendor);
					if (index > -1) {
						vendor = description.substring(index, index + vendor.length());
					}

					description = description.replaceAll("(?i)"+product, " <START:product>" + product + "<END> ");					
					if (description.contains(product)) {
						pflag = true;
					}
					if (vendor.compareTo(product) != 0) {
						description = description.replaceAll("(?i)"+vendor, " <START:vendor>" + vendor + "<END> ");
						vflag = true;
					}
				}
				else {
					product = " "+StringUtil.getStringName(tmp[0])+" ";
					
					int index = StringUtils.indexOfIgnoreCase(description, product);
					if (index > -1) {
						product = description.substring(index, index + product.length());
					}
					
					description = description.replaceAll("(?i)"+product, " <START:product>" + product + "<END> ");					
					if (description.contains(product)) {
						pflag = true;
					}
				}
			}

		}
		
		File trainData = new File("vendor-product.train");
		
		if (pflag || vflag) {
			try {
//				FileUtils.writeStringToFile(trainData, vulnLib.getRefId()+" "+description+"\n", StandardCharsets.UTF_8, true);
				FileUtils.writeStringToFile(trainData, description+"\n", StandardCharsets.UTF_8, true);
			} catch (IOException e) {
				e.printStackTrace();
			}
			pflag = false;
			vflag = false;
		}

	}
	
	/**
	 * model 학습시키기
	 * @throws IOException 
	 */
	private void trainModel() throws IOException {
		MarkableFileInputStreamFactory inputStreamFactory = new MarkableFileInputStreamFactory(new File("vendor-product.train"));
		ObjectStream<String> lineStream = new PlainTextByLineStream(inputStreamFactory, StandardCharsets.UTF_8);
		TokenNameFinderModel model = null;
		TokenNameFinderFactory nameFinderFactory = new TokenNameFinderFactory();

		try (ObjectStream<NameSample> sampleStream = new NameSampleDataStream(lineStream)) {
			model = NameFinderME.train("en", null, sampleStream, TrainingParameters.defaultParams(), nameFinderFactory);
		} catch(Exception e) {
			e.printStackTrace();
		}
		if (model == null) {
			log.error("model not created..");
			return;
		}
		
		File modelFile = new File("vendor-product.model");
		FileOutputStream out = new FileOutputStream(modelFile); 
		
		try (BufferedOutputStream modelOut = new BufferedOutputStream(out)) {
		  model.serialize(modelOut);
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

}
