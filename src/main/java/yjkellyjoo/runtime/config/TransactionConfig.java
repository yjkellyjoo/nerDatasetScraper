/**
 * Copyright (c) 2018 IoTcube, Inc.
 * All right reserved.
 *
 * This software is the confidential and proprietary information of IoTcube, Inc. 
 * You shall not disclose such Confidential Information and
 * shall use it only in accordance with the terms of the license agreement
 * you entered into with IoTcube, Inc.
*/

package yjkellyjoo.runtime.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.aspectj.lang.annotation.Aspect;
import org.springframework.aop.Advisor;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.interceptor.DefaultTransactionAttribute;
import org.springframework.transaction.interceptor.RollbackRuleAttribute;
import org.springframework.transaction.interceptor.RuleBasedTransactionAttribute;

import lombok.extern.slf4j.Slf4j;

/**
 * 
 * @author 	hyeonggookim
 * @since 	2019. 1. 3.
 */
@Slf4j
@Aspect
@Configuration
public class TransactionConfig {
	
    private static final int TX_METHOD_TIMEOUT = 60*150;
    private static final String AOP_POINTCUT_EXPRESSION = "execution(* *..*Service.*(..))";

    @Autowired
    private DataSourceTransactionManager transactionManager;

    @Bean
    public TransactionInterceptor txAdvice() {

    	TransactionInterceptor txAdvice = new TransactionInterceptor();
    	Properties txAttributes = new Properties();

    	List<RollbackRuleAttribute> rollbackRules = new ArrayList<RollbackRuleAttribute>();
    	rollbackRules.add(new RollbackRuleAttribute(Exception.class));

    	/** If need to add additional exception, add here **/
    	DefaultTransactionAttribute readOnlyAttribute = new DefaultTransactionAttribute(TransactionDefinition.PROPAGATION_REQUIRED);
    	readOnlyAttribute.setReadOnly(true);
    	readOnlyAttribute.setTimeout(TX_METHOD_TIMEOUT);

        RuleBasedTransactionAttribute writeAttribute = new RuleBasedTransactionAttribute(TransactionDefinition.PROPAGATION_REQUIRED, rollbackRules);
        writeAttribute.setTimeout(TX_METHOD_TIMEOUT);

		String readOnlyTransactionAttributesDefinition = readOnlyAttribute.toString();
		String writeTransactionAttributesDefinition = writeAttribute.toString();

		log.info("Read Only Attributes :: {}", readOnlyTransactionAttributesDefinition);
		log.info("Write Attributes :: {}", writeTransactionAttributesDefinition);

		// read-only
		txAttributes.setProperty("retrieve*", readOnlyTransactionAttributesDefinition);
		txAttributes.setProperty("select*", readOnlyTransactionAttributesDefinition);
		txAttributes.setProperty("get*", readOnlyTransactionAttributesDefinition);
		txAttributes.setProperty("list*", readOnlyTransactionAttributesDefinition);
		txAttributes.setProperty("search*", readOnlyTransactionAttributesDefinition);
		txAttributes.setProperty("find*", readOnlyTransactionAttributesDefinition);
		txAttributes.setProperty("count*", readOnlyTransactionAttributesDefinition);

		// write rollback-rule
		txAttributes.setProperty("manage*", writeTransactionAttributesDefinition);
		txAttributes.setProperty("create*", writeTransactionAttributesDefinition);
		txAttributes.setProperty("update*", writeTransactionAttributesDefinition);
		txAttributes.setProperty("delete*", writeTransactionAttributesDefinition);
//		txAttributes.setProperty("do*", writeTransactionAttributesDefinition);

		txAdvice.setTransactionAttributes(txAttributes);
		txAdvice.setTransactionManager(transactionManager);

        return txAdvice;

    }

    @Bean
    public Advisor txAdviceAdvisor() {

        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        log.info("txAdviceAdvisor()");
        pointcut.setExpression(AOP_POINTCUT_EXPRESSION);
        return new DefaultPointcutAdvisor(pointcut, txAdvice());

    }
}
