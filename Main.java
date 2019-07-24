import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

public class Main {
	
	public static void main(String[] args) throws NamingException {
		ActiveDirectoryUserVerifier activeDirectory = new ActiveDirectoryUserVerifier(
				"password",
				"domainName");		
		
		System.out.println(activeDirectory.verifyLdapUser("accountName"));
	}
}
