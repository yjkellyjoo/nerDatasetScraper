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

import yjkellyjoo.runtime.controller.DataTableGridParameter;

import lombok.Getter;
import lombok.Setter;

/**
 * CVE 검색 조건
 * @author 	hyeonggookim
 * @since 	2019. 2. 26.
 */
@Getter
@Setter
public class CveSearchOption extends DataTableGridParameter {

	private String keyword;
}
