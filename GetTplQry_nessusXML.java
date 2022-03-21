/*
Retrieve reletive data from NVD database for further calculation.
Author(s) : Su Zhang, Xinming Ou
Copyright (C) 2011, Argus Cybersecurity Lab, Kansas State University

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Iterator;
import java.sql.ResultSetMetaData;

public class GetTplQry_nessusXML {

	public static void main(String[] args) {
		String filename = "vulInfo.txt";
		File f = new File(filename);
		String path = f.getPath();
		String cvdid ="";
		String hostname = "";
		try {
			BufferedReader breader= new BufferedReader(new FileReader(path));
			ArrayList<String> cvePort= new ArrayList<String>();
			while ((cvdid = breader.readLine()) != null) {
				cvePort.add(cvdid); //put all of the cve ids and port info into the arrayList
			}
			writeTpls(cvePort);
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}

	public static void writeAccount(ArrayList<String> hosts) {
    	try {
    		String victim = "";
    		FileWriter fr= new FileWriter("accountinfo.P");
    		Iterator<String> hostItr = hosts.iterator();
    		String host = "";
    		while(hostItr.hasNext()) {
    			host = hostItr.next();
    			victim = "'" + host + "_victim'";
	            fr.write("inCompetent(" + victim+").\n");
	            fr.write("hasAccount(" + victim + ", '" + host + "', user).\n");
	    	    fr.write("attackerLocated(internet).\n");
	    	    fr.write("attackGoal(execCode('" + host + "', _)).\n");
    		}
            fr.close();
    	}
    	catch (Exception e) {
    		e.printStackTrace();
    	}
    }

	public static void writeTpls(ArrayList<String> al) throws Exception {
		String access="";
		String lose_types="";
		String severity="";
		String range="";
		String products="";
		String port ="";
		String prot ="";
		String host = "";
		String cve = "";
		String vulInfos = "";
		boolean hasvuln_exists_7 = false;
		boolean hasvuln_exists_9 = false;
		ArrayList<String> hosts= new ArrayList<String>();
		try {
			int l = al.size();
			FileWriter fr = new FileWriter("results.P");
			String tuple = "";
			for(int i = 0; i < l; i += 5) {
				host = al.get(i);
				if(!hosts.contains(host))
					hosts.add(host);
				cve = al.get(i+1);
				
				//Récupération des infos sur les vulns
				vulInfos = al.get(i+2);
				vulInfos = vulInfos.substring(1, vulInfos.length()-1); //On enlève les accolades
				String[] vulInfos_tmp = vulInfos.split(", ");
				severity = vulInfos_tmp[0].split("=")[1];
				lose_types = vulInfos_tmp[1].split("=")[1];
				access = vulInfos_tmp[2].split("=")[1];
				range = vulInfos_tmp[3].split("=")[1];
				if (vulInfos_tmp.length == 5) {
					products = vulInfos_tmp[4].split("=")[1];
				} else {
					products = "no_products";
				}
				
				port = al.get(i+3);
			    prot =  al.get(i+4);
			    
			    if(range.contains("remoteExploit") && (!range.contains("user_action_req"))) {
					tuple = "vuln_exists('"+host+"','"+cve+"','"+products+"',["+range+"],["+lose_types+"],'"+severity+"','"+access+"','"+port+"','"+prot+"').\n";
					hasvuln_exists_9 = true;
				}
				else {
					tuple="vuln_exists('"+host+"','"+cve+"','"+products+"',["+range+"],["+lose_types+"],'"+severity+"','"+access+"').\n";
					hasvuln_exists_7 = true;
				}
				System.out.println(tuple);
				fr.write(tuple);
			}
			if (!hasvuln_exists_9) {
				fr.write("vuln_exists(null,null,null,null,null,null,null,null,null).");
			}
			if (!hasvuln_exists_7) {
				fr.write("vuln_exists(null,null,null,null,null,null,null).");
			}
			fr.close();
			writeAccount(hosts);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
