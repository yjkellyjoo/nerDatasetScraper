/**
 * Copyright (c) 2018 IoTcube, Inc.
 * All right reserved.
 *
 * This software is the confidential and proprietary information of IoTcube, Inc.
 * You shall not disclose such Confidential Information and
 * shall use it only in accordance with the terms of the license agreement
 * you entered into with IoTcube, Inc.
*/

package yjkellyjoo.runtime.controller;

import lombok.Getter;
import lombok.Setter;

/**
 * Datatable 파라미터
 * @author 	hyeonggookim
 * @since 	2019. 2. 26.
 */
@Getter
@Setter
public class DataTableGridParameter {

	private int draw;	// draw counter
	private int start;	// paging first record indicator
	private int length;	// number of records that the table can display
	private String orderColumn;	// 정렬 컬럼
	private String orderDir;	// 정렬 순서
	private int recordCnt;
}
