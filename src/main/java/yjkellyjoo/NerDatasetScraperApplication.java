package yjkellyjoo;


import javax.annotation.Resource;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import yjkellyjoo.vuln.service.ScraperService;

@SpringBootApplication
public class NerDatasetScraperApplication implements CommandLineRunner {

	@Resource(name="yjkellyjoo.vuln.service.ScraperService")
	private ScraperService scraperService;
	
	public static void main(String[] args) {
		SpringApplication.run(NerDatasetScraperApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		scraperService.perform();
	}
}
