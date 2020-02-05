package yjkellyjoo.runtime.controller;

import lombok.Getter;
import lombok.Setter;

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
