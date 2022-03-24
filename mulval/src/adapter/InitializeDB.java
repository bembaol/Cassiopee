/*
Create a database storing the NVD data
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

import java.sql.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.io.Reader;

import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class InitializeDB {

	public static Connection getConnection() throws SQLException,
	  java.lang.ClassNotFoundException, IOException {
		Class.forName("com.mysql.cj.jdbc.Driver");
		String url = "";
		String userName = "";
		String password = "";
		String MulvalRootEnv = System.getenv("MULVALROOT");
		File f = new File("config.txt");
		String path = f.getPath();
		BufferedReader breader = new BufferedReader(new FileReader(path));
		url = breader.readLine();
		userName = breader.readLine();
		password = breader.readLine();
		Connection con = DriverManager.getConnection(url, userName, password);
		breader.close();
		return con;	
	}

	public static void main(String[] args) {
		setupDB(Integer.parseInt(args[0]));
	}

	public static void setupDB(int year) {
		try {
			Connection con = getConnection();
			Statement sql = con.createStatement();
			sql.execute("drop table if exists nvd");                                                                                                                                                                                                        //,primary key(id)
			sql.execute("create table nvd(id varchar(20) not null,vector varchar(100) not null default 'undefined',availability varchar(100) not null default 'undefind',confidentiality varchar(100) not null default 'undefind',integrity varchar(100) not null default 'undefind',severity varchar(20) not null default 'unefined',complexity varchar(20) not null default 'unefined');");
			
			for(int ct = 2002; ct <= year; ct++) {
				String cveID = "";
				String access = "";
				String severity = "";
				String host = "localhost";
				String vect = "";
                String vect_tmp = "";
				String avail = "";
				String conf = "";
				String integ = "";
				String fname="nvd_json_files/nvdcve-1.1-"+Integer.toString(ct)+".json";
				FileReader reader = new FileReader(fname);
				JSONParser jsonParser = new JSONParser();
	            JSONObject jsonObject = (JSONObject) jsonParser.parse(reader);
	 
	            // get an array from the JSON object
	            JSONArray cveItems = (JSONArray) jsonObject.get("CVE_Items");
	 
	            // take the elements of the json array
	            for (int i = 0; i < cveItems.size(); i++) {
	            	JSONObject cve0 = (JSONObject) cveItems.get(i);
	                
	                //looking for cveID
	                JSONObject cve = (JSONObject) cve0.get("cve");
	                JSONObject cveMetaData = (JSONObject) cve.get("CVE_data_meta");
	                cveID = (String) cveMetaData.get("ID");
	                
	                //Parsing CVSS
	                JSONObject impact = (JSONObject) cve0.get("impact");
	                JSONObject bmV3 = (JSONObject) impact.get("baseMetricV3");
	                JSONObject bmV2 = (JSONObject) impact.get("baseMetricV2");
	                if (bmV3 == null && bmV2 == null) {
	                	continue;
	                } else if (bmV3 == null && bmV2 != null) {
	                	severity = (String) bmV2.get("severity");
	                	JSONObject cvssV2 = (JSONObject) bmV2.get("cvssV2");
	                	access = (String) cvssV2.get("accessComplexity");
		                
		                //Attack vector
		                vect = (String) cvssV2.get("accessVector");
		                if (vect.equals("ADJACENT_NETWORK"))
		    				vect_tmp = "lan";
		    			else if (vect.equals("NETWORK"))
		    				vect_tmp = "remoteExploit";
		    			else if (vect.equals("LOCAL"))
		    				vect_tmp = "local";
		    			else
		    				vect_tmp = "other";
		                vect = vect_tmp;
		                
		                //Impact metrics
		                avail = (String) cvssV2.get("availabilityImpact");
		                conf = (String) cvssV2.get("confidentialityImpact");
		                integ = (String) cvssV2.get("integrityImpact");
	                } else {
	                	JSONObject cvssV3 = (JSONObject) bmV3.get("cvssV3");
		                //Attack Severity
		                severity = (String) cvssV3.get("baseSeverity");
		                
		                //Attack complexity
		                access = (String) cvssV3.get("attackComplexity");
		                
		                //Attack vector
		                vect = (String) cvssV3.get("attackVector");
		                if (vect.equals("PHYSICAL"))
		    				vect_tmp = "user_action_req";
		    			else if (vect.equals("ADJACENT_NETWORK"))
		    				vect_tmp = "lan";
		    			else if (vect.equals("NETWORK"))
		    				vect_tmp = "remoteExploit";
		    			else if (vect.equals("LOCAL"))
		    				vect_tmp = "local";
		    			else
		    				vect_tmp = "other";
		                vect = vect_tmp;
		                
		                //Impact metrics
		                avail = (String) cvssV3.get("availabilityImpact");
		                conf = (String) cvssV3.get("confidentialityImpact");
		                integ = (String) cvssV3.get("integrityImpact");
	                }
	                
	                //Insert les données dans la table
	                String insert = "insert nvd values('" + cveID + "','"
							+ vect + "','" + avail + "','" + conf + "','" + integ
							+ "','" + severity + "','" + access + "')";
	                System.out.println(insert);
					sql.execute(insert);
				}
			}
			
			sql.close();
			con.close();
			
		} catch (java.lang.ClassNotFoundException e) {
			System.err.println("ClassNotFoundException:" + e.getMessage());
		} catch (SQLException ex) {
			System.err.println("SQLException:" + ex.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}
	}

	public static void clearEntryWithVulsoft(String filename) {
		try {
			SAXReader saxReader = new SAXReader();
			Document document = saxReader.read(filename);
			List soft = document
					.selectNodes("/*[local-name(.)='nvd']/*[local-name(.)='entry']/*[local-name(.)='vuln_soft']");
			Iterator sft = soft.iterator(); 
			Element nvd = (Element) document
					.selectSingleNode("/*[local-name(.)='nvd']");
			while (sft.hasNext()) {
				Element vsft = (Element) sft.next();
				nvd.remove(vsft.getParent());
				XMLWriter output = new XMLWriter(new FileWriter(filename));//
				output.write(document);
				output.flush();
				output.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}