package yjkellyjoo.runtime.dao;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;

import lombok.Getter;

@Getter
public abstract class IoTcubeDaoSupport {

	@Autowired
	private SqlSessionTemplate sqlSession;

}
