/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author hcadavid
 */
public class Main {
    
    public static void main(String a[]){
        //HostBlackListsValidator hblv=new HostBlackListsValidator();
        Integer ocurrences = 0;
        List<Integer> blackListOcurrences = new ArrayList<>();
        Thread thread = new Thread(new HostBlackListsValidator("200.24.34.55", 0, 80000, 0, blackListOcurrences));
        //List<Integer> blackListOcurrences=hblv.checkHost("200.24.34.55", 80000);
        thread.start();
//      System.out.println("The host was found in the following blacklists:"+blackListOcurrences);
        
    }
    
}
