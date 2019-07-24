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

import java.sql.Timestamp;

import lombok.Getter;
import lombok.Setter;

/**
 * Product Value Object
 * @author 	yjkellyjoo
 * @since 	2019. 2. 19.
 */
@Getter
@Setter
public class ProductVo {
	private String language;
	private String repository;
	private String productKey;
	private String latestVersion;
	private String name;
	private String description;
	private String license;
	private Timestamp created;
	private Timestamp lastUpdated;	// TODO: 이 테이블에 이건 왜 있는거였지?
	private boolean processed = false;

}
