package br.com.exemplos.springboot;

import java.util.TimeZone;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import jakarta.annotation.PostConstruct;

/**
 * Classe que inicializa a aplicação Spring Boot
 */
@SpringBootApplication
public class SpringApplication {

	/**
	 * Metódo Main que a JVM chamará quando a aplicação for executada.
	 * 
	 * @param args Array de argumentos que podem ser passados durante a chamada do
	 *             método main.
	 */
	public static void main(String[] args) {
		// Executa a aplicação Spring Boot
		org.springframework.boot.SpringApplication.run(SpringApplication.class, args);
	}
	
	@PostConstruct
    public void init() {
        // Define o fuso horário UTC-3 (America/Sao_Paulo)
        TimeZone.setDefault(TimeZone.getTimeZone("America/Sao_Paulo"));
        System.out.println("Fuso horário padrão: " + TimeZone.getDefault().getID());
    }
}