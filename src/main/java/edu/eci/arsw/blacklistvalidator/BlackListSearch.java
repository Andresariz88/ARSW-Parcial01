package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

public class BlackListSearch {

    public static void main(String[] args) throws InterruptedException {

        int N = 100;

        Integer occurrences = new Integer(0);
        String ipaddress = "212.24.24.55";//"200.24.34.55";
        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();
        Thread thread;
        int total = HostBlacklistsDataSourceFacade.getInstance().getRegisteredServersCount();
        List<Integer> blackListOcurrences = new ArrayList<>();

        int range = total / N;
        int min = 0;
        int max = range;
        for (int i = 0; i < N; i++) {
            if (i == N - 1 && (N % 2 != 0)) {
                thread = new Thread(new HostBlackListsValidator(ipaddress, min, max + (N % 2), occurrences, blackListOcurrences));
            } else {
                thread = new Thread(new HostBlackListsValidator(ipaddress, min, max, occurrences, blackListOcurrences));
            }
            min += range;
            max += range;
            thread.start();
        }



        if (occurrences >= 5) {
            skds.reportAsNotTrustworthy(ipaddress);
        } else {
            skds.reportAsTrustworthy(ipaddress);
        }

    }
}
