/**
 * Copyright (c) 2018 IoTcube, Inc.
 * All right reserved.
 *
 * This software is the confidential and proprietary information of IoTcube, Inc.
 * You shall not disclose such Confidential Information and
 * shall use it only in accordance with the terms of the license agreement
 * you entered into with IoTcube, Inc.
*/

package yjkellyjoo.runtime.util;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;

/**
 * 메시지 유틸 (국제화 대비)
 * @author 	hyeonggookim
 * @since 	2018. 11. 27.
 */
@Component
public class MessageUtil implements InitializingBean  {

	@Autowired
	private MessageSource messageSource;

	private static MessageSource mSource;

	/**
	 * 메시지 반환, 파라미터 포함
	 * @param messageCode
	 * @param args
	 * @return
	 */
	public static String getMessage(String messageCode, Object[] args) {
		return mSource.getMessage(messageCode, args, LocaleContextHolder.getLocale());
		// 무조건 영어로 나오게 처리 (2018.11.28)
		// return mSource.getMessage(messageCode, args, Locale.ENGLISH);
	}

	/**
	 * 메시지 반환
	 * @param messageCode
	 * @return
	 */
	public static String getMessage(String messageCode) {
		return getMessage(messageCode, null);
	}

	/* (non-Javadoc)
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	@Override
	public void afterPropertiesSet() throws Exception {

		mSource = messageSource;
	}
}
