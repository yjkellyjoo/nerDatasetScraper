package yjkellyjoo.vuln.service;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Pattern;

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
	
	private final String NAME = "<START:name>";
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
		String result = new String(cve.getDescriptionString());

		for (int i = 0; i < vulnLibInfo.size(); i++) {
			ProductVo productVo = productDao.selectProduct(vulnLibInfo.get(i).getLangauage(), vulnLibInfo.get(i).getRepository(), vulnLibInfo.get(i).getProductKey());
			log.debug("productVo: {}, {}, {} ", vulnLibInfo.get(i).getLangauage(), vulnLibInfo.get(i).getRepository(), vulnLibInfo.get(i).getProductKey());
			
			if (cve.getId().equals("CVE-2016-9910")) {
				boolean flag=true;
			}
			if (vulnLibInfo.get(i).getLangauage().compareTo("javascript") == 0) {
				result = this.manageProductKey(productVo.getName(), result);
			} else {
				result = this.manageProductKey(productVo.getProductKey(), result);
			}
		}
		
		// double space 정리
		result = result.replaceAll("  ", " ");
		
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
	private String manageProductKey(String productKeySplit, String description) {
		String[] names;
		String result;
		
		names = StringUtil.getStringNames(productKeySplit);
		result = this.keyArrangement(this.arrangeNames(names), description, NAME);
			
		// 위 방법으로 검출이 안될 경우 '-' 단위로 잘라서 한번 더..
		if (!result.toString().contains(END)) {
			names = StringUtil.getStringNamesIncludeDash(productKeySplit);
			result = this.keyArrangement(this.arrangeNames(names), description, NAME);
		}
		
		return result;
	}
	
	/**
	 * 이름들 정리하기
	 * @param names
	 * @return
	 */
	private String[] arrangeNames(String[] names) {
		
		// 흔한 이름 정리 
		String[] tmp = names.clone();
		for (String name : names) {
			boolean flag = this.checkException(name);
			if (flag) {
				tmp = ArrayUtils.removeElement(tmp, name);
			}
		}
		
		// 겹치는 경우 정리 
		LinkedHashSet<String> linked = new LinkedHashSet<>(Arrays.asList(tmp));
		String[] result = linked.toArray(new String[] {});
		
		// 숫자만 있는 경우 정리
		for (String name : result) {
			if (Pattern.matches("[^a-zA-Z]+", name)) {
				result = ArrayUtils.removeElement(result, name);
			}
		}
		
		return result;
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
	 * 
	 * @param str
	 * @param description
	 * @param type
	 */
	private String keyArrangement(String[] names, String description, final String type) {	

		for (int i = names.length; i > 0; i--) {
			int startIndex = 0;
			int endIndex = i;
			int count = names.length - i + 1;
			boolean checkChange = false; 
			
			while ( count != 0 ) {
				final String[] INBETWEENS = {" ", "/", ":", "."};
				for (String inBetween : INBETWEENS) {
					StringBuffer name = new StringBuffer("");
					for (int j = startIndex; j < endIndex; j++) {
						name.append(names[j] + inBetween);
					}
					name.delete(name.length()-1, name.length());

					int index = StringUtils.indexOfIgnoreCase(description, name.toString());
					// description에서 정보 발견 
					if (index > -1) {
						name.replace(0, name.length()+1, description.substring(index, index + name.length()));
						// 정보 입력 
						int beginIndexEnd = index+name.length()+1;
						// Span이 겹치지 않는지 확인 
						String cmpEnd = new String(description.substring(beginIndexEnd, description.length()));
						int indEnd = cmpEnd.indexOf(END);
						int indName = cmpEnd.indexOf(NAME);
						if ((indEnd == -1 && indName == -1) || (indEnd > indName && indName != -1)) {
							StringBuffer tmp = new StringBuffer(description);
							tmp.replace(index, index+name.length(), " "+type +" "+ name.toString()+" " + END+" ");
							description = new String(tmp.toString());
//								description = new String(description.replace(name, " "+type +" "+ name.toString()+" " + END+" "));
							checkChange = true;
						}
					}
				}
				startIndex++;
				endIndex++;
				count--;
			}
			
			if (checkChange) {
				return description;				
			}
		}
		
		return description;
		
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
