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
import java.util.Properties;
import java.util.regex.Pattern;

import javax.annotation.Resource;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.*;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;
import edu.stanford.nlp.ie.crf.CRFClassifier;
import edu.stanford.nlp.ling.CoreLabel;
import edu.stanford.nlp.pipeline.*;
import edu.stanford.nlp.sequences.SeqClassifierFlags;
import edu.stanford.nlp.util.logging.RedwoodConfiguration;
import edu.stanford.nlp.util.StringUtils;

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

	private static final String BNAME = "\tB-NAME";
	private static final String INAME = "\tI-NAME";
	private static final String OUT = "\t0";

	
	/**
	 * VULN_LIBRARY 정보 조회
	 */
	public void perform() {
		log.debug("performing... ");
		
		List<VulnLibraryVo> vulnLibList = vulnLibraryDao.selectAllVulnLibraryList();
		for (VulnLibraryVo vulnLibraryVo : vulnLibList) {
			log.debug("VULN_LIB: {} ", vulnLibraryVo.getRefId() );
			try {
				this.manageStanford(vulnLibraryVo);
				this.manageApache(vulnLibraryVo);
			} catch (Exception e) {
				e.printStackTrace();
				log.error(vulnLibraryVo.getRefId());
			}
		}
		
//		try {
//			this.trainApache();
//		} catch (IOException e) {
//			e.printStackTrace();
//			log.error("problem while handling files...");
//		}
//		this.trainStanford();
	}


	/**
	 * CVE 정보에서 description 부분 training data
	 * @param vulnLib
	 */
	private void manageApache(VulnLibraryVo vulnLib) {
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
//			log.debug("productVo: {}, {}, {} ", tmp.getLangauage(), tmp.getRepository(), tmp.getProductKey());

			boolean flag = true;
			for (int i = 0; i < vulnLibInfo.size(); i++) {
				if (vulnLibInfo.get(i).getProductKey().compareTo(tmp.getProductKey()) == 0) {
					flag = false;
				}
			}
			if (flag) {
				vulnLibInfo.add(tmp);
//				log.debug("added");

			}
		}
		
		// description에 vendor와 product 정보 기입 

		CveVo cve = cveDao.selectCve(vulnLib.getRefId());
		String result = new String(cve.getDescriptionString());

		for (int i = 0; i < vulnLibInfo.size(); i++) {
			ProductVo productVo = productDao.selectProduct(vulnLibInfo.get(i).getLangauage(), vulnLibInfo.get(i).getRepository(), vulnLibInfo.get(i).getProductKey());
			log.debug("productVo: {}, {}, {} ", vulnLibInfo.get(i).getLangauage(), vulnLibInfo.get(i).getRepository(), vulnLibInfo.get(i).getProductKey());
			
//			if (cve.getId().equals("CVE-2002-1148")) {
//				boolean flag=true;
//			}

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
	 * CVE 정보에서 description 부분 training data
	 * @param vulnLib
	 */
	private void manageStanford(VulnLibraryVo vulnLib) {
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
			log.debug("productVo: {}, {}, {} ", tmp.getLangauage(), tmp.getRepository(), tmp.getProductKey());

			boolean flag = true;
			for (int i = 0; i < vulnLibInfo.size(); i++) {
				if (vulnLibInfo.get(i).getProductKey().compareTo(tmp.getProductKey()) == 0) {
					flag = false;
				}
			}
			if (flag) {
				vulnLibInfo.add(tmp);
				log.debug("added");
			}
		}
		
		// description에 name 정보 기입 
		CveVo cve = cveDao.selectCve(vulnLib.getRefId());
		String description = new String(cve.getDescriptionString());
		
		// description String tokenize
	    Properties props = new Properties();
	    props.setProperty("annotators", "tokenize,ssplit");
	    
	    RedwoodConfiguration.current().clear().apply();
		StanfordCoreNLP pipeline = new StanfordCoreNLP(props);
		CoreDocument doc = new CoreDocument(description);
		pipeline.annotate(doc);
		
		StringBuffer descBuffer = new StringBuffer();

		for (int i = 0; i < doc.sentences().size(); i++) {
			List<CoreLabel> tokens = doc.sentences().get(i).tokens();
			int tokenSize = tokens.size();
			
			int j = 0;
			String result[][] = new String[2][tokenSize];
			for (CoreLabel token : tokens) {
				result[0][j] = token.word();
				result[1][j] = OUT;
				j++;
			}
			
			// name 정보 기입 
			for (int k = 0; k < vulnLibInfo.size(); k++) {
				ProductVo productVo = productDao.selectProduct(vulnLibInfo.get(k).getLangauage(), vulnLibInfo.get(k).getRepository(), vulnLibInfo.get(k).getProductKey());
				log.debug("productVo: {}, {}, {} ", vulnLibInfo.get(k).getLangauage(), vulnLibInfo.get(k).getRepository(), vulnLibInfo.get(k).getProductKey());
				
//				if (cve.getId().equals("CVE-2019-10310")) {
//					boolean flag=true;
//				}
				
				if (vulnLibInfo.get(k).getLangauage().compareTo("javascript") == 0) {
					result = this.manageProductKey(productVo.getName(), result);
				} else {
					result = this.manageProductKey(productVo.getProductKey(), result);
				}
			}
			
			for (int k = 0; k < result[0].length; k++) {
				descBuffer.append(result[0][k]);
				descBuffer.append(result[1][k]);
				descBuffer.append("\n");
			}
		}
//		description = desc.toString();
		
		// description 문장들 file로 저장 
		try {
			if (descBuffer.toString().contains(BNAME)) {
				File trainData = new File("product_names.train");

//				FileUtils.writeStringToFile(trainData, vulnLib.getRefId()+"\n"+descBuffer.toString()+"\n", StandardCharsets.UTF_8, true);
				FileUtils.writeStringToFile(trainData, descBuffer.toString()+"\n", StandardCharsets.UTF_8, true);
			} else {
				File trainData = new File("noinfo.train");
				FileUtils.writeStringToFile(trainData, vulnLib.getRefId()+"\n"+description+"\n", StandardCharsets.UTF_8, true);
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
		result = this.keyArrangement(this.arrangeNames(names), description);
			
		// 위 방법으로 검출이 안될 경우 '-' 단위로 잘라서 한번 더..
		if (!result.toString().contains(END)) {
			names = StringUtil.getStringNamesIncludeDash(productKeySplit);
			result = this.keyArrangement(this.arrangeNames(names), description);
		}
		
		return result;
	}

	
	/**
	 * description에 vendor와 product 정보 기입 
	 * @param productKeySplit
	 * @param description
	 * @return
	 */
	private String[][] manageProductKey(String productKeySplit, String[][] description) {
		String[] names;
		String[][] result;
		
		names = StringUtil.getStringNamesIncludeDash(productKeySplit);
		result = this.keyArrangement(this.arrangeNames(names), description);
		
		return result;
	}
	
	/**
	 * 이름들 정리하기
	 * @param names
	 * @return
	 */
	private String[] arrangeNames(String[] names) {
		
//		// 흔한 이름 정리 
//		String[] tmp = names.clone();
//		for (String name : names) {
//			boolean flag = this.checkException(name);
//			if (flag) {
//				tmp = ArrayUtils.removeElement(tmp, name);
//			}
//		}
		
		// 겹치는 경우 정리 
//		LinkedHashSet<String> linked = new LinkedHashSet<>(Arrays.asList(tmp));
//		LinkedHashSet<String> linked = new LinkedHashSet<>(Arrays.asList(names));
//		String[] result = linked.toArray(new String[] {});
		String[] result = names;
		
		// 숫자만 있는 경우 정리
		for (String name : result) {
			if (Pattern.matches("[^a-zA-Z]+", name)) {
				result = ArrayUtils.removeElement(result, name);
			}
		}
		
		// 너무 짧은 이름 정리
		for (String name : result) {
			if (name.length() < 3) {
				result = ArrayUtils.removeElement(result, name);
			}
		}
		
		return result;
	}
	
	
	/**
	 * 
	 * @param str
	 * @param description
	 */
	private String keyArrangement(String[] names, String description) {	
		
		for (int i = names.length; i > 0; i--) {
			int startIndex = 0;
			int endIndex = i;
			int count = names.length - i + 1;
			boolean checkChange = false; 
			
			while ( count != 0 ) {
				final String[] INBETWEENS = {" ", ".", "_"};
				for (String inBetween : INBETWEENS) {
					StringBuffer name = new StringBuffer("");
					for (int j = startIndex; j < endIndex; j++) {
						name.append(names[j] + inBetween);
					}
					name.delete(name.length()-1, name.length());

					int index = org.apache.commons.lang3.StringUtils.indexOfIgnoreCase(description, name.toString());
					// description에서 정보 발견 
					if (index > -1) {
						name.replace(0, name.length()+1, description.substring(index, index + name.length()));
						// Span이 겹치지 않는지 확인 
						int beginIndexEnd = index+name.length();
						String cmpEnd = new String(description.substring(beginIndexEnd, description.length()));
						int indEnd = cmpEnd.indexOf(END);
						int indName = cmpEnd.indexOf(NAME);
						if ((indEnd == -1 && indName == -1) || (indEnd > indName && indName != -1)) {

							// 괄호 안에 있거나, 단독 단어일 경우에만 저장 
							try {
								boolean before = description.substring(index-1, index).matches("[ (]");
								boolean after = description.substring(index+name.length(), index+name.length()+1).matches("[ )]");
								if (before && after) {
									StringBuffer tmp = new StringBuffer(description);
									tmp.replace(index, index+name.length(), " "+NAME+" " + name.toString() + " "+END+" ");
									description = new String(tmp.toString());
//										description = new String(description.replace(name, " "+type +" "+ name.toString()+" " + END+" "));
									checkChange = true;								
								}					
							} catch(StringIndexOutOfBoundsException e) {
								StringBuffer tmp = new StringBuffer(description);
								tmp.replace(index, index+name.length(), " "+NAME+" " + name.toString() + " "+END+" ");
								description = new String(tmp.toString());
//								description = new String(description.replace(name, " "+type +" "+ name.toString()+" " + END+" "));
								checkChange = true;	
							}
						}
					}
				}
				startIndex++;
				endIndex++;
				count--;
			
				if (checkChange) {
					return description;				
				}
			}
		}
		return description;
		
	}
	
	
	/**
	 * 
	 * @param str
	 * @param description
	 */
	private String[][] keyArrangement(String[] names, String[][] description) {	
		
		// 제일 긴 Noun Phrase 서부터 하나씩 검출하기 
		for (int i = names.length; i > 0; i--) {
			int startIndex = 0;
			int endIndex = i;
			int count = names.length - i + 1;
			
			while ( count != 0 ) {
				
				// (1) NP delimiter가 ., -, /인 경우 확인 
				final String[] INBETWEENS = {".", "-", "/"};
				for (String inBetween : INBETWEENS) {
					StringBuffer name = new StringBuffer("");
					for (int j = startIndex; j < endIndex; j++) {
						name.append(names[j] + inBetween);
					}
					name.delete(name.length()-1, name.length());

					// description에서 정보 검출하기 
					int[] nameIndex = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
					int c = 0;
					for (int j = 0; j < description[0].length; j++) {
						if (description[0][j].toLowerCase().contains(name.toString().toLowerCase())) {
							nameIndex[c] = j;
							c++;
						}
					}
					
					if (nameIndex[0] != -1) {
						for (int j = 0; j < c; j++) {
							if (description[1][nameIndex[j]].compareTo(OUT) == 0) {
								description[1][nameIndex[j]] = BNAME;
							}
						}
					}
				}
				
				for (int j = 0; j < description[0].length; j++) {
					if (description[0][j].toLowerCase().compareTo(names[startIndex].toLowerCase()) == 0) {
						// (2) NP delimiter가 " "인 경우 확인 
						int full = 1;
						for (int k = startIndex+1; k < endIndex; k++) {
							if (description[0][j+full].toLowerCase().compareTo(names[k].toLowerCase()) == 0) {
								full++;
							} else {
								break;
							}
						}
						
						if (full == i && description[1][j].compareTo(OUT) == 0) {
							description[1][j] = BNAME;
							for (int k = 1; k < i; k++) {
								description[1][j+k] = INAME;
							}
						}
						
						// (3) NP delimiter가 "_"인 경우 확인 
						full = 2;
						for (int k = startIndex+1; k < endIndex; k++) {
							try {
								boolean same = description[0][j+full].toLowerCase().compareTo(names[k].toLowerCase()) == 0;
								if ((description[0][j+full-1].compareTo("_") == 0) && same) {
									full+=2;
								} else {
									break;
								}
							} catch (ArrayIndexOutOfBoundsException e) {
								full-=2;
								break;
							}
						}
							
						if (full == i*2 && description[1][j].compareTo(OUT) == 0) {
							description[1][j] = BNAME;
							for (int k = 2; k < full; k+=2) {
								description[1][j+k] = INAME;
							}
						}
					}
				}
				
				startIndex++;
				endIndex++;
				count--;				

			}
		}
		
		return description;
	}

	
	/**
	 * model 학습시키기
	 * @throws IOException 
	 */
	private void trainStanford() {
		String prop = "product_names.prop";
		String modelOutPath = "product-ner-model.ser.gz";
		String trainingFilepath = "product_names.train";
		
		Properties props = StringUtils.propFileToProperties(prop);
		props.setProperty("serializeTo", modelOutPath);
		props.setProperty("trainFile", trainingFilepath);
	
		SeqClassifierFlags flags = new SeqClassifierFlags(props);
		CRFClassifier<CoreLabel> crf = new CRFClassifier<>(flags);
		crf.train();
		crf.serializeClassifier(modelOutPath);
	}
	

	/**
	 * model 학습시키기
	 * @throws IOException 
	 */
	private void trainApache() throws IOException {
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
		
		File modelFile = new File("ner-organizations.bin");
		FileOutputStream out = new FileOutputStream(modelFile); 
		
		try (BufferedOutputStream modelOut = new BufferedOutputStream(out)) {
		  model.serialize(modelOut);
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
}
