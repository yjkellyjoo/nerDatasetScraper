/**
 * Copyright (c) 2018 IoTcube, Inc.
 * All right reserved.
 *
 * This software is the confidential and proprietary information of IoTcube, Inc.
 * You shall not disclose such Confidential Information and
 * shall use it only in accordance with the terms of the license agreement
 * you entered into with IoTcube, Inc.
*/

package yjkellyjoo.vuln.model;

import yjkellyjoo.runtime.util.DateUtil;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 *
 * @author 	hyeonggookim
 * @since 	2019. 2. 25.
 */
@Getter
@Setter
@NoArgsConstructor
public class VulnLibraryInfo {

	private String langauage;
	private String repository;
	private String productKey;
	private String version;
	private String saveDtime;

	public VulnLibraryInfo(VulnLibraryRequest request) {
		this.langauage = request.getLanguage();
		this.repository = request.getRepository();
		this.productKey = request.getProductKey();
		this.version = request.getVersion();
		this.saveDtime = DateUtil.now();

	}
}
