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
import java.util.List;

import lombok.Getter;
import lombok.Setter;

/**
 * 
 * @author 	hyeonggookim
 * @since 	2019. 2. 25.
 */
@Getter
@Setter
public class VulnLibraryVo {

//	private int vulnLibraryId;
	private String vulnSourceCd;
	private String refId;
	private List<VulnLibraryInfo> vulnLibraryInfos;
	private Timestamp created;
	private Timestamp lastUpdated;
}
