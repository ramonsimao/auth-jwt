package br.com.exemplos.springboot.rest.json;

/**
 * Classe que representa o JSON retornada pelo geração do Token através do
 * serviço {@link AuthService}.
 */
public class AccessToken {
	
	/**
	 * Hash do Token de Acesso,
	 */
	private String token;
	
	/**
	 * Tempo em milissegundos em que o token é válido. Se superar esse tempo, o
	 * token deixa de ser válido.
	 */
	private long expire_in;
	
	/**
	 * Tipo da autorização do Token.
	 */
	private String type;

	/**
	 * Contrutor que inicializa os atributos da classe.
	 * 
	 * @param token     Hash do Token de Acesso,
	 * @param expire_in Tempo em milissegundos em que o token é válido. Se superar
	 *                  esse tempo, o token deixa de ser válido.
	 * @param type      Tipo da autorização do Token.
	 */
	public AccessToken(String token, long expire_in, String type) {
		super();
		this.token = token;
		this.expire_in = expire_in;
		this.type = type;
	}

	/**
	 * @return the token
	 */
	public String getToken() {
		return token;
	}

	/**
	 * @param token the token to set
	 */
	public void setToken(String token) {
		this.token = token;
	}

	/**
	 * @return the expire_in
	 */
	public long getExpire_in() {
		return expire_in;
	}

	/**
	 * @param expire_in the expire_in to set
	 */
	public void setExpire_in(long expire_in) {
		this.expire_in = expire_in;
	}

	/**
	 * @return the type
	 */
	public String getType() {
		return type;
	}

	/**
	 * @param type the type to set
	 */
	public void setType(String type) {
		this.type = type;
	}
}
