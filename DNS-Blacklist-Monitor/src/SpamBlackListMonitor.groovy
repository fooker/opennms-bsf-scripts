#!/usr/bin/env groovy
import groovy.time.TimeCategory
import groovy.time.TimeDuration

import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.Future
/**
 * Multi-threaded monitor to check if a specific IP address is registered
 * on a DNS Realtime Blacklist (DNSRBL) service. The monitor uses the
 * reverse IP DNS lookups against a set of DNSRBL provider. For DNS lookup
 * the InetAddress.getByName is used.
 *
 * For example:
 * ------------
 * Check if a mail server with the IP address 87.226.224.34 is registered
 * on bl.spamcop.net would be
 *
 *   host 34.224.226.87.bl.spamcop.net
 *   34.224.226.87.bl.spamcop.net has address 127.0.0.2
 *
 * If the reverse address has an A record the IP address for the mail server
 * is on the block list. If you don't have an A record the server is not
 * blocked.
 *
 * The monitor does not support IPv6.
 *
 * @author Ronny Trommer (ronny@opennms.org)
 * @since 1.0-SNAPSHOT
 */
// Amount of Threads you want to use for the DNS lookups
MAX_THREADS = 10

/**
 * Class with a lookup result. It represents a result from DNSRBL lookup.
 */
class LookupResult {

    /**
     * Name of the DNS real time blacklist provider
     */
    String blProvider = null;

    /**
     * Flag if the blacklist provider has the IP address on his block list
     */
    boolean isBlacklisted;

    /**
     * The response time for the DNS lookup
     */
    TimeDuration lookupTime = null

    /**
     * A clean output of the lookup result
     *
     * @return attributes as {@link java.lang.String}
     */
    @Override
    def String toString() {
        return "DNSRBL provider = [${blProvider}]; Is black listed = [${isBlacklisted}], Resolve time = [${lookupTime.toMilliseconds()} ms]"
    }
}

/**
 * Closure for parallel blacklist lookups
 */
def myClosure = { blProvider, ipAddress -> blackListLookup(ipAddress, blProvider) }

/**
 * IP address to test
 */
def ipAddress = '87.226.224.34'
// def ipAddress = '31.15.64.120'

/**
 * Collection with DNSRBL lookup results
 */
def Collection<LookupResult> blacklistResultList = null;

/**
 * Thread pool for DNS lookups
 */
def threadPool = Executors.newFixedThreadPool(MAX_THREADS)

/**
 * Start time for total time measurement
 */
def timeStart = new Date()

/**
 * List with all DNSRBL provider
 */
def dnsRblProviderList = [
        'b.barracudacentral.org',
        'bl.emailbasura.org',
        'bl.spamcannibal.org',
        'bl.spamcop.net',
        'blackholes.five-ten-sg.com',
        'blacklist.woody.ch',
        'bogons.cymru.com',
        'cbl.abuseat.org cdl.anti-spam.org.cn',
        'combined.abuse.ch combined.rbl.msrbl.net',
        'db.wpbl.info',
        'dnsbl-1.uceprotect.net',
        'dnsbl-2.uceprotect.net',
        'dnsbl-3.uceprotect.net',
        'dnsbl.ahbl.org',
        'dnsbl.cyberlogic.net',
        'dnsbl.inps.de',
        'dnsbl.sorbs.net drone.abuse.ch',
        'drone.abuse.ch',
        'duinv.aupads.org',
        'dul.dnsbl.sorbs.net dul.ru',
        'dyna.spamrats.com dynip.rothen.com',
        'http.dnsbl.sorbs.net',
        'images.rbl.msrbl.net',
        'ips.backscatterer.org ix.dnsbl.manitu.net',
        'korea.services.net',
        'misc.dnsbl.sorbs.net',
        'noptr.spamrats.com',
        'ohps.dnsbl.net.au omrs.dnsbl.net.au orvedb.aupads.org',
        'osps.dnsbl.net.au osrs.dnsbl.net.au owfs.dnsbl.net.au',
        'owps.dnsbl.net.au pbl.spamhaus.org',
        'phishing.rbl.msrbl.net',
        'psbl.surriel.com',
        'rbl.interserver.net rbl.megarbl.net',
        'rdts.dnsbl.net.au relays.bl.gweep.ca',
        'ricn.dnsbl.net.au',
        'rmst.dnsbl.net.au sbl.spamhaus.org',
        'short.rbl.jp',
        'smtp.dnsbl.sorbs.net',
        'socks.dnsbl.sorbs.net spam.abuse.ch',
        'spam.dnsbl.sorbs.net',
        'spam.rbl.msrbl.net',
        'spam.spamrats.com',
        'spamlist.or.kr',
        'spamrbl.imp.ch',
        't3direct.dnsbl.net.au',
        'tor.ahbl.org',
        'tor.dnsbl.sectoor.de',
        'torserver.tor.dnsbl.sectoor.de',
        'ubl.lashback.com',
        'ubl.unsubscore.com',
        'virbl.bit.nl',
        'virus.rbl.jp',
        'virus.rbl.msrbl.net web.dnsbl.sorbs.net',
        'wormrbl.imp.ch',
        'xbl.spamhaus.org',
        'zen.spamhaus.org',
        'zombie.dnsbl.sorbs.net',
        'relays.bl.kundenserver.de',
        'probes.dnsbl.net.au proxy.bl.gweep.ca proxy.block.transip.nl',
        'relays.nether.net residential.block.transip.nl'
]

/**
 * Create DNS hostname to request A record. The IP address is reversed
 * and attached with the DNSRBL provider
 *
 * @param ipAddress IPv4 Address as {@link java.lang.String}
 * @param blProvider DNSRBL provider DNS domain as {@link java.lang.String}
 * @return reverse IP address with DNSRBL domain name as {@link java.lang.String}
 */
def private buildQuery(String ipAddress, String blProvider) {
    // Split IPv4 address in octets
    def ipAddressOctets = ipAddress.split("\\.");
    def reverseIpString = ""

    // Reverse IPv4 octets and append "."
    for (octet in ipAddressOctets.reverse()) {
        reverseIpString += octet + "."
    }

    // Return reversed IPv4 address with DNSRBL provider domain name
    return reverseIpString + blProvider
}

/**
 * Request DNS A record for given IPv4 address for a specific DNSRBL provider
 *
 * @param ipAddress IPv4 address as {@link java.lang.String}
 * @param blProvider Domain name of the DNSRBL provider as {@link java.lang.String}
 * @return lookup result as {@link LookupResult}
 */
def private LookupResult blackListLookup(String ipAddress, String blProvider) {
    // Build the host name for the DNS A record request
    def query = buildQuery(ipAddress, blProvider)

    // Start time measurement for specific DNS A record lookup
    def startLookupTime = new Date()

    // Initialize empty lookup result
    def LookupResult lookupResult = new LookupResult()

    // Try DNS lookup and filling up lookup result
    try {
        lookupResult.blProvider = blProvider

        // DNS A record request
        InetAddress.getByName(query)

        // DNS A record successful, IP address is registered on the DNSRBL provider
        lookupResult.isBlacklisted = true;
    } catch (UnknownHostException e) {

        // No A record found, IP address is not registered on the DNSRBL provider
        lookupResult.isBlacklisted = false;
    }

    // Stop time measurement for specific DNS A record lookup
    def stopLookupTime = new Date()

    // Calculate time difference
    TimeDuration duration = TimeCategory.minus(stopLookupTime, startLookupTime)

    // Fill time measurement in lookup result
    lookupResult.lookupTime = duration

    return lookupResult
}

/**
 * Create output for the monitoring system
 *
 * @param blacklistResultList
 *      with all DNS lookup results for all DNSRBL provider as {@link java.util.Collection}
 * @return Output for monitoring system as {@link java.lang.String}
 */
def private String buildMonitoringOutput(Collection blacklistResultList) {
    def output = ""

    // Iterate on all DNS lookup results
    for (blacklistResult in blacklistResultList) {
        if (blacklistResult.isBlacklisted) {
            // IP address is registered on a black list
            if ("".equals(output)) {
                // first entry
                output += "NOK, ${blacklistResult.blProvider}"
            } else {
                // 2nd + entry
                output = "${output}, ${blacklistResult.blProvider}"
            }
        }
    }

    if ("".equals(output)) {
        // The IP address is not registered on any of the DNSRBL provider
        output = "OK"
    } // At least one DNSRBL provider has the IPv4 address registered and blocks the IP

    return output
}

try {
    // Try to make lookups with parallel threads
    List<Future> futures = dnsRblProviderList.collect { blProvider ->
        threadPool.submit({ ->
            myClosure blProvider, ipAddress
        } as Callable);
    }

    // Get all results from threads
    blacklistResultList = futures.collect { it.get() } as Collection<LookupResult>
} finally {
    threadPool.shutdown()
}

// Stop total time measurement
def timeStop = new Date()

// Calculate time duration
TimeDuration duration = TimeCategory.minus(timeStop, timeStart)

// Output result
println "${duration.toMilliseconds()}, " + buildMonitoringOutput(blacklistResultList)
