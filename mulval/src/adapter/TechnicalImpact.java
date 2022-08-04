
//look for the technical impacts associated to a prompted CVE.

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class TechnicalImpact {
	public List<String> Consequencies;
	
	public TechnicalImpact(String cve) {
			this.Consequencies=CVE(cve);
			}
		
	public static void main(String[] args) {
		TechnicalImpact impact= new TechnicalImpact(args[0]);
		display(impact.Consequencies);
	}
	
	public static void display(List<String> list) { //fonction utilis�e pour afficher les cons�quences de la CVE regroup�es dans une liste de String appel�e Consequencies
		if(list.size()==1) {
			System.out.println(list.get(0));
		} else {
			for (int i=0;i<list.size();i++) {
				System.out.println(list.get(i));
				}
		}
	}
	
	public static List<String> getCWEs(StringBuilder sb) {     //fonction permettant de r�cup�rer son forme de liste les lien url des CWEs associ�es � la CVE � partir du code html de la page web de la CVE sur le site du NIST
	int i=0;
	int pos=0;
	int previous_pos=0;
	int pos2=0;
	String res="";
	String finder,finder2;
	List<String> CWEs = new ArrayList<>();
	while (res!="No CWE") {
		previous_pos=pos;
		finder="\""+ "vuln-CWEs-link-"+i+"\"";
		pos=sb.indexOf(finder,pos+1)+finder.length()+26;
		if (pos>=previous_pos && pos>=10000) {
			finder2="NVD-CWE-Other";                               //Il s'agit d'une CWE qui n'a pas correctement été explicité sur le site du NIST (notamment pour des CVEs anciennes)
			pos2=sb.indexOf(finder2,pos-finder.length()-26);
			if (pos2<=10000) {                                     //N'étant pas référencée, on considère qu'elle ne possède pas de Technical impact selon le NIST
				res=sb.substring(pos,sb.indexOf("\" target=",pos));
		    	CWEs.add(res);
			} else {
				res="No CWE";CWEs.add(res);
				break;
			}
	    	
	    } else {
	    	res="No CWE";
	    	CWEs.add(res);
	    	break;
	    }
		i++;
	}
	return CWEs;
}
	
	public static List<String> getConsequencies(StringBuilder sb) {     //fonction permettant de r�cup�rer les cons�quences d'une CWE � partir du code html associ� � la description de la CWE par le site web du NIST
		int pos;
		int previous_pos;
		String res;
		String[] finder={"nowrap>Availability<br></td>","nowrap>Availability<br>Other<br></td>","nowrap>Integrity<br></td>","nowrap>Integrity<br>Other<br></td>","nowrap>Confidentiality<br></td>","nowrap>Confidentiality<br>Other<br></td>","nowrap>Integrity<br>Confidentiality<br></td>","nowrap>Integrity<br>Confidentiality<br>Other<br></td>","nowrap>Confidentiality<br>Integrity<br></td>","nowrap>Confidentiality<br>Integrity<br>Other<br></td>","nowrap>Availability<br>Confidentiality<br></td>","nowrap>Availability<br>Confidentiality<br>Other<br></td>","nowrap>Availability<br>Integrity<br></td>","nowrap>Availability<br>Integrity<br>Other<br></td>","nowrap>Confidentiality<br>Availability<br></td>","nowrap>Confidentiality<br>Availability<br>Other<br></td>","nowrap>Integrity<br>Availability<br></td>","nowrap>Integrity<br>Availability<br>Other<br></td>","nowrap>Integrity<br>Confidentiality<br>Availability<br></td>","nowrap>Integrity<br>Confidentiality<br>Availability<br>Other<br></td>"};
		String[] values= {"Availability","Availability","Integrity","Integrity","Confidentiality","Confidentiality","Integrity;Confidentiality","Integrity;Confidentiality","Confidentiality;Integrity","Confidentiality;Integrity","Availability;Confidentiality","Availability;Confidentiality","Availability;Integrity","Availability;Integrity","Confidentiality;Availability","Confidentiality;Availability","Integrity;Availability","Integrity;Availability","Integrity;Confidentiality;Availability","Integrity;Confidentiality;Availability"};
		String[] results;
		List<String> Consequencies = new ArrayList<>();
		for (int i=0; i<finder.length;i++) {
			pos=0;
			previous_pos=0;
			res="";
			while (! res.equals("No Consequency")) {
				previous_pos=pos;
				try {
					pos=sb.indexOf(finder[i],pos+1);
				} catch(Exception e) {
					Consequencies.add("No Consequency");
					return Consequencies;
				}
				if (pos>=previous_pos && pos>=1000) {
					results=values[i].split(";");
					for (int j=0;j<results.length;j++) {
						if (Consequencies.contains(results[j])==false) {
							res=results[j];
							Consequencies.add(results[j]);
						}
					}
			    } else {
			    	res="No Consequency";
			    	break;
			    }
			}
		}
		return Consequencies;
	}
	
	public static String TypeImpact(String impact) {
		String[] split=impact.split(" ");
		List<String> write = Write();
		List<String> read = Read();
		List<String> privescalation = PrivEscalation();
		List<String> serviceinterrupt = ServiceInterrupt();
		List<String> ressourceremoval = RessourceRemoval();
		List<String> indirectdisclosure = IndirectDisclosure();
		String res="";
		if(write.contains(split[0])) {
			res="Write: "+ impact;
		}
		else if (read.contains(split[0])) {
			res="Read: "+ impact;
		}
		else if (privescalation.contains(split[0])) {
			res="PrivEscalation: "+ impact;
		}
		else if (serviceinterrupt.contains(split[0])) {
			res="ServiceInterrupt: "+ impact;
		}
		else if (ressourceremoval.contains(split[0])) {
			res="Ressource Removal: "+ impact;
		}
		else if (indirectdisclosure.contains(split[0])) {
			res="Indirect Disclosure: "+ impact;
		}
		else {
			res="Other: "+ impact;
		}
		return res;
	}
	
	public static List<String> Write() {
		List<String> write = new ArrayList<String>();
		write.add("Modify");
		return write;
	}
	
	public static List<String> Read() {
		List<String> read = new ArrayList<String>();
		read.add("Read");
		return read;
	}
	
	public static List<String> PrivEscalation() {
		List<String> privescalation = new ArrayList<String>();
		privescalation.add("Execute");
		privescalation.add("Bypass");
		privescalation.add("Hide");
		privescalation.add("Gain");
		return privescalation;
	}
	
	public static List<String> ServiceInterrupt() {
		List<String> serviceinterrupt = new ArrayList<String>();
		serviceinterrupt.add("DoS:");
		return serviceinterrupt;
	}
	
	public static List<String> RessourceRemoval() {
		List<String> ressourceremoval = new ArrayList<String>();
		return ressourceremoval;
	}
	
	public static List<String> IndirectDisclosure() {
		List<String> indirectdisclosure = new ArrayList<String>();
		return indirectdisclosure;
	}
	
	public static StringBuilder connexion(String url) { //fonction permettant de r�cup�rer le code html de la page web associ� � l'url donn�e en entr�e
		try {
			URL obj = new URL(url);
			HttpURLConnection conn = (HttpURLConnection) obj.openConnection();
			conn.setReadTimeout(5000);
			conn.addRequestProperty("Accept-Language", "en-US,en;q=0.8");
			conn.addRequestProperty("User-Agent", "Mozilla");
			conn.addRequestProperty("Referer", "google.com");
			conn.setInstanceFollowRedirects(true);
			boolean redirect = false;

			// normally, 3xx is redirect
			int status = conn.getResponseCode();
			if (status != HttpURLConnection.HTTP_OK) {
				if (status == HttpURLConnection.HTTP_MOVED_TEMP
					|| status == HttpURLConnection.HTTP_MOVED_PERM
						|| status == HttpURLConnection.HTTP_SEE_OTHER)
				redirect = true;
			}

			if (redirect) {

				// get redirect url from "location" header field
				String newUrl = conn.getHeaderField("Location");

				// get the cookie if need, for login
				String cookies = conn.getHeaderField("Set-Cookie");

				// open the new connection again
				conn = (HttpURLConnection) new URL(newUrl).openConnection();
				conn.setRequestProperty("Cookie", cookies);
				conn.addRequestProperty("Accept-Language", "en-US,en;q=0.8");
				conn.addRequestProperty("User-Agent", "Mozilla");
				conn.addRequestProperty("Referer", "google.com");
			}
			//Apr�s s'�tre connect�, on r�cup�re l'ensemble du code html de la page web dans le string sb
			
			BufferedReader in = new BufferedReader(
		                              new InputStreamReader(conn.getInputStream()));
			 boolean loop = true;
			    StringBuilder sb = new StringBuilder(8096);
			    while (loop) {
			      if (in.ready()) {
			        int i = 0;
			        while (i != -1) {
			          i = in.read();
			          sb.append((char) i);
			        }
			        loop = false;
			      }
			    }
			    return sb;
		} catch (Exception e) {
		//	System.out.println(e);
			System.out.println("No connexion to the domain");
			return null;
		}
	}
	
  public static List<String> CVE(String cve) {
    try {
    	//On cherche tout d'abord � se connecter sur la page du NIST associ�e � la CVE
    	String url = "https://nvd.nist.gov/vuln/detail/"+cve;
    	StringBuilder sb=connexion(url);
	    List<String> CWEs = getCWEs(sb);
	    List<String> Consequencies=new ArrayList<>();
	    List<String> Current_CVE_Consequencies=new ArrayList<String>();
	    //pour chaque CWEs, on cherche les cons�quences associ�es � celles-ci et on les ajoutent dans Consequencies
	    if(CWEs.size()==1) {
	    	Consequencies.add("No Consequency");
	    } else {
	    	for(int i=0;i<CWEs.size()-1;i++) {
	    		sb=connexion(CWEs.get(i));
	    		Current_CVE_Consequencies=getConsequencies(sb);
	    		for(int j=0;j<Current_CVE_Consequencies.size();j++) {
	    			if(Consequencies.contains(Current_CVE_Consequencies.get(j))==false) {
	    				Consequencies.add(Current_CVE_Consequencies.get(j));
	    				}
	    			}
	    		}
	    	}
	    return Consequencies;
	    } catch (Exception e) {
	    	e.printStackTrace();
	    	return null;
	    	}
    }
}
