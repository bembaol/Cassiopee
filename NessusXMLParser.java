/*
Parse the nessus report in XML format and extracts vulnerability information for MulVAL.
Author(s) : Su Zhang
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

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.*;

public class NessusXMLParser {

	public static void main(String[] args) {
		parseNessus(args[0]);
	}

	public static void parseNessus(String nessusReport) {
		try {
			SAXReader saxReader = new SAXReader();
			FileWriter fr = new FileWriter("vulInfo.txt");
			Document document = saxReader.read(nessusReport);
			// Each entry is indexed by one cve_id
			List reportHost = document.selectNodes(
					"/*[local-name(.)='NessusClientData_v2']/*[local-name(.)='Report']/*[local-name(.)='ReportHost']");
			
			Iterator reportHostItrt = reportHost.iterator();
			while (reportHostItrt.hasNext()) {
				Element host = (Element) reportHostItrt.next();
				// Element iterator of each entry
				Iterator ei = host.elementIterator();
				// Put all of the subelements' names(subelement of entry) to an array list(subele)
				while (ei.hasNext()) {
					Element sube = (Element) ei.next();
					if(!sube.getName().equals("ReportItem"))
						continue;
					// A list of elements for each entry
					ArrayList<String> subele = new ArrayList<String>();
					Iterator reportItemItrt = sube.elementIterator();
					while(reportItemItrt.hasNext()) {
						Element reportItemElement = (Element) reportItemItrt.next();
						subele.add(reportItemElement.getName());
					}
					if(subele.size() == 0 || (!subele.contains("cve")))
						continue;
					Iterator itr = sube.elementIterator("cve");
					while(itr.hasNext()) {
						System.out.println("host name is: " + host.attribute(0).getText());
						
						//On ajoute Host
						fr.write(host.attribute(0).getText() + "\n");
						
						Element cve = (Element) itr.next();
						System.out.println(cve.getText());
						
						//On ajoute CVE
						fr.write(cve.getText() + "\n");	
						
						//On récupère le vecteur CVSS 
						Element cvss;
						if (subele.contains("cvss3_vector")) {
							cvss = (Element) sube.elementIterator("cvss3_vector").next();
						} else {
							cvss = (Element) sube.elementIterator("cvss_vector").next();
						}
						HashMap<String, String> vuln = parseCvss(cvss.getText());
						
						//Get all vulnerable products
						String products = "";
						if (subele.contains("cpe")) {
							Element cpe = (Element) sube.elementIterator("cpe").next();
							String[] cpes = cpe.getText().split("\n");
							for (int i=0; i<cpes.length; i++) {
								if (i==cpes.length-1) {
									products = products+parseCpe(cpes[i]);
								} else {
									products = products+parseCpe(cpes[i])+" ";
								}
							}
						}
						
						if (!products.equals("")) {
							vuln.put("products", products);
						}
						
						//Récupérer la séverité 
						Element severity;
						if (subele.contains("cvss3_base_score")) {
							severity = (Element) sube.elementIterator("cvss3_base_score").next();
						} else {
							severity = (Element) sube.elementIterator("cvss_base_score").next();
						}
						vuln.put("severity", severity.getText());
						
						System.out.println(vuln.toString());
						fr.write(vuln.toString() + "\n");
						
						System.out.println("port number is: " + sube.attribute(0).getText());
						fr.write(sube.attribute(0).getText() + "\n");
						System.out.println("protocol is: " + sube.attribute(2).getText());
						fr.write(sube.attribute(2).getText() + "\n");
						System.out.println();
					}
				}
			}
			fr.close();
		} 
		catch (DocumentException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static HashMap<String,String> parseCvss(String vector) throws Exception {
		HashMap<String,String> res = new HashMap<>();
		String[] metrics = vector.split("/");
		String lose_types = "";
		String range = "";
		if (metrics[0].equals("CVSS:3.0")) {
			//Range
			switch(metrics[1].charAt(3)) {
			case 'P':
				range += "'physicalExploit'";
			case 'L':
				range += "'localExploit'";
				break;
			case 'A':
				range += "'adjacentExploit'";
				break;
			case 'N':
				range += "'remoteExploit'";
				break;
			default:
				range += "'other'";
			}
			
			if(metrics[4].charAt(3) == 'R') {
				range += "',user_action_req'";
			}
			
			res.put("range", range);
			
			//Lose_type
			if(metrics[6].charAt(2)!='N') {
				lose_types += "'data_loss',";
			}
			
			if(metrics[7].charAt(2)!='N') {
				lose_types += "'data_modification',";
			}
			
			if(metrics[8].charAt(2)!='N') {
				lose_types += "'availability_loss',";
			}
			int ltp = lose_types.length();
			lose_types = lose_types.substring(0, ltp - 1);// delete the last comma
			res.put("lose_types", lose_types);
			
			//Access
			if (metrics[2].charAt(3)=='L') {
				res.put("access", "l");
			} else {
				res.put("access", "h");
			}
			
			//Au cas où le score CVSS3 n'est pas présent (jamais vu), on utilise le CVSS2
		} else if (metrics[0].split("#")[0].equals("CVSS2")){
			//Range
			switch(metrics[0].charAt(9)) {
			case 'L':
				res.put("range", "'localExploit'");
				break;
			case 'A':
				res.put("range", "'adjacentExploit'");
				break;
			case 'N':
				res.put("range", "'remoteExploit'");
				break;
			}
			
			//Complexity vector
			switch(metrics[1].charAt(3)) {
			case 'L':
				res.put("access", "l");
				break;
			case 'M':
				res.put("access", "m");
				break;
			case 'H':
				res.put("access", "h");
				break;
			}
			
			//lose_types
			if(metrics[3].charAt(2)!='L') {
				lose_types += "'data_loss',";
			}
	
			if(metrics[4].charAt(2)!='L') {
				lose_types += "'data_modification',";
			}
			
			if(metrics[5].charAt(2)!='L') {
				lose_types += "'availability_loss',";
			}
			int ltp = lose_types.length();
			lose_types = lose_types.substring(0, ltp - 1);// delete the last comma
			res.put("lose_types", lose_types);
			
		} else {
			throw new Exception(vector + " is not a CVSS vector");
		}
		
		return res;
	}
	
	public static String parseCpe(String uri) throws Exception {
		String[] features = uri.split(":");
		String res = "";
		if (!features[0].equals("cpe")) {
			throw new Exception(uri + " is not a cpe URI");
		}
		
		//Find the product type
		/* Not really useful
		switch(features[1].charAt(1)) {
		case 'a':
			res+="SW:";
			break;
		case 'o':
			res+="OS:";
			break;
		case 'h':
			res+="HW:";
			break;
		}
		*/
		
		res = /*res + features[2] + " "+ */features[3];
		
		return res;
	}
}
