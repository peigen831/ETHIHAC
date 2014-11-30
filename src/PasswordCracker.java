import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.digest.Sha2Crypt;


public class PasswordCracker {
	private Sha2Crypt shaEncryptor = new Sha2Crypt();
	private HashMap<String, String> userpassMap;	//username and hashed password
	private ArrayList<String> toCrackList;			//username with id>1000
	private ArrayList<String> wordList;				//worst password list
	private HashMap<String, String> crackResult;	//final result username, raw password
	
	
	private String wordPath;
	private String passwdPath;
	private String shadowPath;
	
	public PasswordCracker(String wordPath, String passwdPath, String shadowPath){
		this.wordPath = wordPath;
		this.passwdPath = passwdPath;
		this.shadowPath = shadowPath;
	}
	
	public void startCracking(){
		toCrackList = getValidUserList();
		//printlist(toCrackList);
		
		userpassMap = getAccountMap();
		//printMap(userpassMap);
		
		wordList = getWordList();
		//printlist(wordList);
		
		generateCrackResult();
		
		//printMap(crackResult);
	}
	
	
	
	public void printMap(HashMap<String, String> map){
		for(Map.Entry<String, String> entry : map.entrySet()){
		    System.out.printf("Username : %s  Password: %s %n", entry.getKey(), entry.getValue());
		}
	}
	
	public void printlist(ArrayList<String> list){
		for(int i = 0; i < list.size(); i++ )
			System.out.println(list.get(i));
	}
	
	//cracking raw password
	private void generateCrackResult(){
		//HashMap<String, String> result = new HashMap<String, String>();

		String username;
		String password;
		String salt;
		String hashedWord;
		
		//for each user to be cracked
		for(Map.Entry<String, String> entry : userpassMap.entrySet()){
			username = entry.getKey();
			password = entry.getValue();
			salt = getSalt(password);
			
			if(!salt.equals("!") && !salt.equals("*"))
			{
				//try on each word
				boolean found = false;
				for(int i = 0; i < wordList.size(); i++)
				{
					hashedWord = shaEncryptor.sha512Crypt(wordList.get(i).getBytes(), salt);
					
					if(hashedWord.equals(password))
					{
						System.out.println("Username: " + username + " Password: " + wordList.get(i));
						found = true;
						break;
					}
				}
				if(!found)
					System.out.println("Username: " + username + " Password: PASSWORD NOT IN WORDLIST");
			}
			
			else
				System.out.println("Username: " + username + " Password: " + salt);
		}
		//return result;
	}
	
	//get the salt part from the whole hashed password
	private String getSalt(String shadowPass){
		// Note: need handle * or !
		
		StringBuilder sb = new StringBuilder();
		
		int cnt=0;
		
		if(!shadowPass.equals("!")  && !shadowPass.equals("*"))
		{
		
			for(int i = 0; i < shadowPass.length(); i++)
			{
				if(shadowPass.charAt(i) == '$')
					cnt++;
				
				sb.append(shadowPass.charAt(i));
				
				if(cnt == 3)
					break;
			}
		}
		
		else return shadowPass;
		
		return sb.toString();
	}
	
	//get the given word list from given text file
	private ArrayList<String> getWordList(){
		
		ArrayList<String> wordList = new ArrayList<String>();
		BufferedReader br = null;
		
		try {
			FileReader reader = new FileReader(wordPath);
			br = new BufferedReader(reader);
			
	    	String value;
	    	
	        while ((value = br.readLine()) != null) 
		        wordList.add(value);
	        
			br.close();
	    }catch(Exception e){
	    	e.printStackTrace();
	    }
		
		return wordList;
	}
	
	//get username and hashed password who's ID > 1000 from shadow file
	private HashMap<String, String> getAccountMap(){
		HashMap<String, String> map = new HashMap<String, String>();
		BufferedReader br = null;
		
		try {
			FileReader reader = new FileReader(shadowPath);
			br = new BufferedReader(reader);
			
	    	String line;
	    	
	        while ((line = br.readLine()) != null) 
	        { 
	        	String[] split = line.split(":");
	        	
	        	//add condition if the password is ! or *
	        	if(toCrackList.contains(split[0]))
	        		map.put(split[0], split[1]);
	        }
	        
			br.close();
	    }catch(Exception e){
	    	e.printStackTrace();
	    }
		
		return map;
	}
	
	//get list of username who has ID > 1000 from passwd file
	private ArrayList<String> getValidUserList(){
		
		ArrayList<String> userList = new ArrayList<String>();
		BufferedReader br = null;
		
		try {
			FileReader reader = new FileReader(passwdPath);
			br = new BufferedReader(reader);
			
	    	String line;
	    	
	        while ((line = br.readLine()) != null) 
	        { 
	        	String[] split = line.split(":");
	        	if(Integer.parseInt(split[2]) >= 1000)
	        		userList.add(split[0]);
	        }
	        
			br.close();
	    }catch(Exception e){
	    	e.printStackTrace();
	    }
		
		return userList;
	}
	
	
	public static void main(String args[]){
		//String wordPath = "src/500-worst-passwords.txt";
		//String passwdPath = "src/passwd";
		//String shadowPath = "src/shadow";
		String wordPath = args[0];
		String passwdPath = args[1];
		String shadowPath = args[2];
				
		PasswordCracker cracker = new PasswordCracker(wordPath, passwdPath, shadowPath);
		
		cracker.startCracking();
	}
}
