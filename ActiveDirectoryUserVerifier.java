import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class ActiveDirectoryUserVerifier implements LdapUserVerifier {

	private static final String SAM_ACCOUNT_NAME = "samAccountName";
	private static final String TOP_BASE = "DC=cable,DC=comcast,DC=com";
	
	private DirContext dirContext;
	private SearchControls searchCtls;
	private final String pass;
	private final String domain;
	
	public ActiveDirectoryUserVerifier(String pass, String domain) {
		this.pass = pass;
		this.domain = domain;
		dirContext = newDirectoryContext(pass, domain);
		searchCtls = createSearchControls();
	}
		
	@Override
	public boolean verifyLdapUser(String ntid) {
		NamingEnumeration<SearchResult> poo = searchUser(ntid);
		
		while (poo.hasMoreElements()) {
			try {
				if (containsUser(poo.next(), SAM_ACCOUNT_NAME, ntid)) {
					return true;
				}
			} catch (NamingException e) {
				throw new LdapException("MAYBE CHANGE THIS" + ntid, e);
			}
		}
		return false;
	}
		
	private boolean containsUser(SearchResult result, String attrID, String ntid) {
		Attributes attributes = result.getAttributes();
		if (attributes.size() > 0) {
			Attribute attr = attributes.get(attrID);
			if (attr != null) {
				return attr.contains(ntid);
			}
		}
		return false;
	}
	
	private InitialDirContext newDirectoryContext(String pass, String domain) {		
		Hashtable<String, String> env = createContextMap(pass, domain);
		
		try {
			return new InitialDirContext(env);
		} catch (NamingException e) {
			throw new LdapException("Failed to initialize Directory Context with environment: " + env, e);
		}
	}
	
	private Hashtable<String, String> createContextMap(String pass, String domain) {
		Hashtable<String, String> ldapEnv = new Hashtable<String, String>();

		ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		ldapEnv.put(Context.PROVIDER_URL, domain);
		ldapEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
		ldapEnv.put(Context.SECURITY_PRINCIPAL,
				"CN=!esareporting,OU=Service Accounts,OU=West Chester," + 
				"OU=Corporate,DC=cable,DC=comcast,DC=com");
		ldapEnv.put(Context.SECURITY_CREDENTIALS, pass);
		
		return ldapEnv;
	}
	
	private SearchControls createSearchControls() {
		SearchControls searchCtls = new SearchControls();
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		searchCtls.setReturningAttributes(new String[] { SAM_ACCOUNT_NAME });
		
		return searchCtls;
	}
	
	private NamingEnumeration<SearchResult> searchUser(String ntid) {
		String filter = "(&(objectClass=user)(samAccountName=" + ntid + "))";

		try {
			return this.dirContext.search(TOP_BASE, filter, this.searchCtls);
		} catch (NamingException e) {
			throw new LdapException("Failed to verify user " + ntid, e);
		} 
	}


	public static class LdapException extends RuntimeException {

		public LdapException(String message, Exception e) {
			super(message, e);
		}

		private static final long serialVersionUID = 1L;

	}
}
