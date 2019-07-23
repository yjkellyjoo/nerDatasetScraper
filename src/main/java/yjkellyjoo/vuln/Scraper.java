package yjkellyjoo.vuln;

import javax.annotation.Resource;

import org.springframework.stereotype.Component;

import yjkellyjoo.vuln.service.ScraperService;

/**
 * 
 * @author 	yjkellyjoo
 * @since	2019. 07. 23.
 */
@Component("yjkellyjoo.vuln.Scraper")
public class Scraper {

	@Resource(name = "yjkellyjoo.vuln.service.ScraperService")
	private ScraperService scraperService;
	
	public void startScrap() {
		scraperService.perform();
	}
}
