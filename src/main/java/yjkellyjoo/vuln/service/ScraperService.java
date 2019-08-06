package yjkellyjoo.vuln.service;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.annotation.Resource;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
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
import opennlp.tools.util.Span;
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
	
	private final String VENDOR = "<START:vendor>";
	private final String PRODUCT = "<START:product>";
	private final String END = "<END>";

	
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
		
		// vulnLibInfo list에 한 CVE의 취약한 library 정보 중복 없이 정리 
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
		
		// description에 vendor와 product 정보 기입 
		CveVo cve = cveDao.selectCve(vulnLib.getRefId());
		StringBuffer description = new StringBuffer(cve.getDescriptionString());
		for (int i = 0; i < vulnLibInfo.size(); i++) {
			ProductVo productVo = productDao.selectProduct(vulnLibInfo.get(i).getLangauage(), vulnLibInfo.get(i).getRepository(), vulnLibInfo.get(i).getProductKey());
			log.debug("productVo: {}, {}, {} ", vulnLibInfo.get(i).getLangauage(), vulnLibInfo.get(i).getRepository(), vulnLibInfo.get(i).getProductKey());

			try {
				if (vulnLibInfo.get(i).getLangauage().compareTo("javascript") == 0) {
						String tmp[] = productVo.getName().split("/");
						this.manageProductKey(tmp, description);
				}
				else {
						String tmp[] = productVo.getProductKey().split(":");
						this.manageProductKey(tmp, description);
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
		
		// double space 정리
		String result = description.toString().replaceAll("  ", " ");
		
		// description 문장들 file로 저장 
		try {
			if (result.contains(END)) {
				File trainData = new File("vendor-product.train");

//				FileUtils.writeStringToFile(trainData, vulnLib.getRefId()+" "+result+"\n", StandardCharsets.UTF_8, true);
				FileUtils.writeStringToFile(trainData, result+"\n", StandardCharsets.UTF_8, true);
			} else {
				File trainData = new File("noinfo.train");
				FileUtils.writeStringToFile(trainData, vulnLib.getRefId()+" "+result+"\n", StandardCharsets.UTF_8, true);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * description에 vendor와 product 정보 기입 
	 * @param productKeySplit
	 * @param description
	 * @return
	 */
	private void manageProductKey(String[] productKeySplit, StringBuffer description) {
		String[] vendors, products;
		
		if (productKeySplit.length == 2) {
			vendors = StringUtil.getStringNames(productKeySplit[0]);
			products = StringUtil.getStringNames(productKeySplit[1]);

			this.keyArrangement(products, description, PRODUCT);
			this.keyArrangement(this.dealRepetition(vendors, products), description, VENDOR);
			
		}
		else {
			products = StringUtil.getStringNames(productKeySplit[0]);

			this.keyArrangement(products, description, PRODUCT);
		}
		
		// 위 방법으로 검출이 안될 경우 - 단위로 잘라서 한번 더..
		if (!description.toString().contains(END)) {
			if (productKeySplit.length == 2) {
				vendors = StringUtil.getStringNamesIncludeDash(productKeySplit[0]);
				products = StringUtil.getStringNamesIncludeDash(productKeySplit[1]);

				this.keyArrangement(products, description, PRODUCT);
				this.keyArrangement(this.dealRepetition(vendors, products), description, VENDOR);
			}
			else {
				products = StringUtil.getStringNamesIncludeDash(productKeySplit[0]);

				this.keyArrangement(products, description, PRODUCT);
			}
		}

	}
	
	/**
	 * vendor 이름이 product랑 겹치는 경우 건너띄기
	 * @param vendors
	 * @param products
	 * @return
	 */
	private String[] dealRepetition(String[] vendors, String[] products) {
		String[] tmp = vendors.clone();
		for (String product : products) {
			for (String vendor : vendors) {					
				boolean flag = this.checkException(vendor);
				if (flag) {
					continue;
				}
				
				if(StringUtils.containsIgnoreCase(product, vendor)) {
					tmp = ArrayUtils.removeElement(tmp, vendor);
				}
			}
		}
		return tmp;
	}
	
	/**
	 * 
	 * @param str
	 * @param description
	 * @param type
	 */
	private void keyArrangement(String[] str, StringBuffer description, final String type) {		
		// 대소문자 구분을 위해..
		for (String name : str) {
			// 흔한 이름 제외..
			boolean flag = this.checkException(name);
			if (flag) {
				continue;
			}
			
			int index = StringUtils.indexOfIgnoreCase(description, name);
			if (index > -1) {
				// 특수사항 제외 - tar로 START에 일부 읽히는 경우 
				if(description.substring(index, index+name.length()).equals(name.toUpperCase())) {
					continue;
				}
				name = description.substring(index, index + name.length());
				// 정보 입력 
				int beginIndexEnd = index+name.length()+1;
				int beginIndexStart = index-2;
				try {
					String cmpEnd = new String(description.substring(beginIndexEnd, beginIndexEnd+END.length()));
					String cmpStart = new String(description.substring(beginIndexStart, beginIndexStart+1));
					if (cmpEnd.compareTo(END) != 0 && cmpStart.compareTo(">") != 0) {
						description.replace(index, index + name.length(), " "+type +" "+ name+" " + END+" ");
					}
				} catch (StringIndexOutOfBoundsException e) {
					description.replace(index, index + name.length(), " "+type +" "+ name+" " + END+" ");
					continue;
				}

			}
		}			
	}
	
	/**
	 * 흔한 이름 정리하기 
	 * @param name
	 * @return
	 */
	private boolean checkException(String name) {
		return StringUtils.equalsIgnoreCase(name, "apache") || StringUtils.equalsIgnoreCase(name, "com") 
		|| StringUtils.equalsIgnoreCase(name, "org") || StringUtils.equalsIgnoreCase(name, "net")
		|| StringUtils.equalsIgnoreCase(name, "rt") || StringUtils.equalsIgnoreCase(name, "api")
		|| StringUtils.equalsIgnoreCase(name, "ro");
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
