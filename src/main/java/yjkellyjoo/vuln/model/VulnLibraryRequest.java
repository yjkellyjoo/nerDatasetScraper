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

import lombok.Getter;
import lombok.Setter;

/**
 * 취약점 저장 요청 용
 * @author 	hyeonggookim
 * @since 	2019. 2. 27.
 */
@Getter
@Setter
public class VulnLibraryRequest {

	private String language;
	private String repository;
	private String productKey;
	private String version;
	private boolean affected;
}
