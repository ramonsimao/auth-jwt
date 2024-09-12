package br.com.exemplos.springboot.rest;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.Date;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.JWTVerifier;

import br.com.exemplos.springboot.rest.json.AccessToken;

//Marca a Classe como um Controlador RESTful
@RestController

//Mapeia a URL da API de Autorização e geração de Tokens.
@RequestMapping("api/v1/auth")

/**
 * Classe que controla o mapeamento de uma API RESTful.
 */
public class AuthService {
	
	/**
	 * Chave RSA pública.
	 */
	private static final RSAPublicKey rsaPublicKey;
	
	/**
	 * Chave RSA privada.
	 */
	private static final RSAPrivateKey rsaPrivateKey;
	
	/**
	 * Executa o bloco estático para a inicialização dos atributos de classa
	 * estáticos.
	 */
	static {
		try {
			RSAKey[] RSA_KEYS = inicializarRSAKeys();
			rsaPublicKey = (RSAPublicKey) RSA_KEYS[0];
			rsaPrivateKey = (RSAPrivateKey) RSA_KEYS[1];
		} catch (NoSuchAlgorithmException exception) {
			throw new RuntimeException(); 
		}
	}
	
	/**
	 * Inicializa as chave publica e privada pelo algorítimo RSA.
	 * 
	 * @return Um array de {@link RSAKey} onde o primeiro elemento a chave pública
	 *         ({@link RSAPublicKey}) e o segundo é a chave privada
	 *         ({@link RSAPrivateKey}).
	 * @throws NoSuchAlgorithmException Caso não seja possível obter a instância do
	 *                                  {@link KeyPairGenerator} pelo algorítimo
	 *                                  RSA.
	 */
	private static final RSAKey[] inicializarRSAKeys() throws NoSuchAlgorithmException {
		// Cria o array com tamanho 2 para receber as chaves pública e privada.
		final RSAKey[] KEYS = new RSAKey[2];
		
		// Gera e inicializa o par de chaves do algorítimo "RSA" 
		final KeyPairGenerator KPG = KeyPairGenerator.getInstance("RSA");
		KPG.initialize(1024);
		
		// Atribui as chaves geradas ao Array de Retorno.
		final KeyPair KP = KPG.generateKeyPair();
		KEYS[0] = (RSAPublicKey) KP.getPublic();
		KEYS[1] = (RSAPrivateKey) KP.getPrivate();
		
		return KEYS;
	}

	/**
	 * Método que representa um recurso HTTP que atende pelo verbo "POST" no recurso
	 * nomeado por "/access-token", recebe um corpo
	 * ("application/x-www-form-urlencoded") com os cabeçalhos necessários para
	 * solicitar a criação de um Access Token que será retornado no formato
	 * "application/json".
	 * 
	 * @param body Corpo da requisição que deverá conter os segintes atributos:
	 *             <ul>
	 *             <li><b>grant_type</b> - client_credentials</li>
	 *             <li><b>client_id</b> - Id da credencial para a geração do
	 *             Token</li>
	 *             <li><b>client_secret</b> - Senha da credencial para a geração do
	 *             Token</li>
	 *             </ul>
	 * @return Um Response do tipo "application/json" contendo as definidas pela
	 *         classe {@link AccessToken}
	 */
	@PostMapping(
			value = "/access-token", 
			consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, 
			produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.TEXT_PLAIN_VALUE})
	public ResponseEntity<?> gerarToken(@RequestBody(required = true) MultiValueMap<String, String> body) {
		final String USUARIO = body.get("client_id").get(0);
		final String SENHA = body.get("client_secret").get(0);
		final long EXPIRES_TIME_MLS = 3600;
		Date dateExpire = null;
		String token = null;

		// Valida a credencial
		if (!verificarCredenciais(USUARIO, SENHA))
			return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);

		try {
			// Inicializa o algorítimo.
			Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, rsaPrivateKey);

			// Gera o Token pelo Algorítimo RSA.
			Builder jwtBuilder = JWT.create();
			dateExpire = new Date(System.currentTimeMillis() + (EXPIRES_TIME_MLS*1000));
			jwtBuilder.withExpiresAt(dateExpire);
			jwtBuilder.withIssuer("auth0");
			token = jwtBuilder.withIssuer("auth0").sign(algorithm);
			return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
					.body(new AccessToken(token, EXPIRES_TIME_MLS, "Bearer"));
		} catch (Exception exception) {
			// Retorna o motivo do token não ter sido gerado
			return ResponseEntity.internalServerError().contentType(MediaType.TEXT_PLAIN)
					.body("[" + new Date() + "-" + dateExpire + "] : " + exception.getMessage());
		}
	}
	
	/**
	 * Método que representa um recurso HTTP que atende pelo verbo "POST" no recurso
	 * nomeado por "/validate", recebe nos cabeçalhos da requisição o header de
	 * Autorização contendo o hash do token para validação.
	 * 
	 * @param token Representa o HEADER Authorization para validação.
	 * @return Um Response do tipo "text/plain" informando o motivo do token não ser
	 *         válido ou de não ter sido possível validar.
	 */
	@PostMapping(value = "/validate", 
			produces = MediaType.TEXT_PLAIN_VALUE)
	public ResponseEntity<?> validarToken(@RequestHeader(name = "Authorization") String token) {
		try {
			token = token.replaceAll("Bearer ", "");
		    Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, rsaPrivateKey);
		    JWTVerifier verifier = JWT.require(algorithm)
		        // specify any specific claim validations
		        .withIssuer("auth0")
		        // reusable verifier instance
		        .build();
		        
		    verifier.verify(token);
		    return ResponseEntity.ok().build();
		} catch (JWTVerificationException exception){
			return new ResponseEntity<>(LocalDateTime.now() + " : " + exception.getMessage(), HttpStatus.UNAUTHORIZED);
		}
	}

	/**
	 * Verifica se a credencial informada é válida para que ai sim seja possível
	 * passar para a etapa de geração do token.
	 * 
	 * @param usuario Usuário identificador da credencial.
	 * @param senha   Senha da credencial.
	 * @return {@literal true} se a credencial for válida.
	 */
	private boolean verificarCredenciais(String usuario, String senha) {
		if (usuario.equals("FCS0438") && senha.equals("Lg@kp500"))
			return true;
		return false;
	}
}