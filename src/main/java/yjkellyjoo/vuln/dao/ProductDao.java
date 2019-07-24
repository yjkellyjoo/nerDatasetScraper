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

import yjkellyjoo.vuln.model.ProductVo;
import yjkellyjoo.runtime.dao.IoTcubeDaoSupport;

/**
 * TB_PRODUCT 관리 DAO 클래스
 * @author 	yjkellyjoo
 * @since 	2019. 2. 19.
 */
@Repository("yjkellyjoo.vuln.dao.ProductDao")
public class ProductDao extends IoTcubeDaoSupport {

    /**
	 * TB_PROUCT 목록 나눠서 조회
	 * @param start
	 * @param end
	 * @return
     */
    public List<ProductVo> selectNotProcessedProductListInLimit(int start, int end, String prefix, String lang, String repo) {

		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("start", start);
		paramMap.put("end", end);
		paramMap.put("prefix", prefix);
		paramMap.put("language", lang);
		paramMap.put("repository", repo);

    	return getSqlSession().selectList("yjkellyjoo.vuln.dao.ProductDao.selectNotProcessedProductListInLimit", paramMap);
    }

    public List<ProductVo> selectProductListInLimit(int start, int end, String lang, String repo) {

		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("start", start);
		paramMap.put("end", end);
		paramMap.put("language", lang);
		paramMap.put("repository", repo);

    	return getSqlSession().selectList("yjkellyjoo.vuln.dao.ProductDao.selectProductListInLimit", paramMap);
    }

    public ProductVo selectProduct(String language, String repository, String productKey) {

		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("language", language);
		paramMap.put("repository", repository);
		paramMap.put("productKey", productKey);

    	return getSqlSession().selectOne("yjkellyjoo.vuln.dao.ProductDao.selectProduct", paramMap);
    }

    /**
     * 모든 TB_PROUCT 조회
     * @return
     */
    public List<ProductVo> selectAllProductList(String language, String repository) {

    	Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("language", language);
		paramMap.put("repository", repository);

    	return getSqlSession().selectList("yjkellyjoo.vuln.dao.ProductDao.selectAllProductList", paramMap);
    }


    /**
     * TB_MAVEN_ARCHIVE 테이블에서 해당 repositoryName의 product를 TB_PRODUCT로 로딩하기
     * @return
     */
	public int insertAllProductFromMaven(String repositoryName) {

		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("repository", "MAVEN");
		paramMap.put("language", "NPM");
		paramMap.put("repositoryName", repositoryName);

    	return getSqlSession().insert("yjkellyjoo.vuln.dao.ProductDao.insertAllProductFromMaven", paramMap);

	}

	/**
     * TB_PRODUCT 여러건 등록
	 * @param productList
	 * @return
	 */
	public int insertProductList(List<ProductVo> productList) {

		return getSqlSession().insert("yjkellyjoo.vuln.dao.ProductDao.insertProductList", productList);
	}

	/**
     * TB_PRODUCT 단건 등록
	 * @param product
	 */
	public void insertProduct(ProductVo product) {

		getSqlSession().insert("yjkellyjoo.vuln.dao.ProductDao.insertProduct", product);
	}


	/**
	 * TB_PRODUCT 갱신
	 * @param product
	 */
	public void updateProduct(ProductVo product) {

		getSqlSession().update("yjkellyjoo.vuln.dao.ProductDao.updateProduct", product);
	}

	public void updateProductToUnprocessed(ProductVo product) {

		getSqlSession().update("yjkellyjoo.vuln.dao.ProductDao.updateProductToUnprocessed", product);
	}


	/**
	 * TB_PRODUCT 다수 갱신
	 * @param product
	 */
	public void updateProductList(List<ProductVo> productList) {

		getSqlSession().update("yjkellyjoo.vuln.dao.ProductDao.updateProductList", productList);
	}


    /**
     * TB_PRODUCT 비우기
     */
    public void deleteAllProduct(String language, String repository) {

    	Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("language", language);
		paramMap.put("repository", repository);

        getSqlSession().delete("yjkellyjoo.vuln.dao.ProductDao.deleteAllProduct", paramMap);
    }


    /**
     * TB_PRODUCT 단건 지우기
     */
    public void deleteProduct(String language, String repository, String productKey) {

		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("productKey", productKey);
		paramMap.put("language", language);
		paramMap.put("repository", repository);

        getSqlSession().delete("yjkellyjoo.vuln.dao.ProductDao.deleteProduct", paramMap);
    }
}
