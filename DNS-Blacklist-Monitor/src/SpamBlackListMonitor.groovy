#!/usr/bin/env groovy
import groovy.transform.Immutable

import java.time.Duration
import java.time.Instant
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Multi-threaded monitor to check if a specific IP address is registered
 * on a DNS Blackhole List (DNSBL) service. The monitor uses the reverse
 * IP DNS lookups against a set of DNSBL provider. For DNS lookup the
 * InetAddress.getByName() method is used.
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
 * is on the block list of the given DNSBL server. If you don't have an
 * A record the server is not blocked.
 *
 * The monitor does not support IPv6.
 *
 *
 * The following variables are passed into the script from OpenNMS:
 *
 *   map         - a Map object that contains all the various parameters passed
 *                 to the monitor from the service definition in the
 *                 poller-configuration.xml file
 *   ip_addr     - the IP address that is currently being polled.
 *   node_id     - the Node ID of the node the ip_addr belongs to
 *                 node_label - this nodes label
 *   node_label -  this nodes label
 *   svc_name    - the name of the service that is being polled
 *   bsf_monitor - the instance of the BSFMonitor object calling the script,
 *                 useful primarily for purposes of logging via its
 *                 log(String sev, String fmt, Object... args) method.
 *   results     - a hash map (string, string) that the script may use to pass its
 *                 results back to the BSFMonitor - the status indication should be
 *                 set into the entry with key "status", and for status indications
 *                 other than "OK," a reason code should be set into the entry with
 *                 key "reason"
 *   times       - an ordered hash map (string, number) that the script may use to
 *                 pass one or more response times back to the BSFMonitor
 *
 * @author Ronny Trommer (ronny@opennms.org)
 * @author Dustin Frisch (dustin@opennms.com)
 * @since 1.0-SNAPSHOT
 */

/**
 * Class with the lookup result for a particular. It represents a result from DNSBL
 * lookup which contains the queried provider, a flag if the address was blacklisted
 * by that provider and the lookup duration for that provider.
 */
@Immutable
class LookupResult {

    /**
     * Name of the DNS real time blacklist provider
     */
    String provider

    /**
     * Flag if the blacklist provider has the IP address on his block list
     */
    boolean listed

    /**
     * The response time for the DNS lookup
     */
    long duration
}

// Initialize poller status with UNKNOWN --> Service down
results.put('status', 'UNK')

// Amount of Threads for parallel DNS lookups
final threads = map.get('threads', 10) as int

// Get the timeout configuration
final timeout = map.get('timeout', 30000) as int

// Load the address to check
final address = InetAddress.getByName(ip_addr)

// Determine and load the the list of DNSBL providers
final String[] providers
switch (address) {
    case Inet4Address: providers = (map.get('providers.v4', 'dnsbl-providers-v4') as File) as String[]; break
    case Inet6Address: providers = (map.get('providers.v6', 'dnsbl-providers-v6') as File) as String[]; break
    default: return
}

// Generate the query from the reversed IP address
final String[] query
switch (address) {
    case Inet4Address: query = address.address.toList().collect(Byte.&toUnsignedInt).collect(Integer.&toString); break
    case Inet6Address: query = address.address.toList().collect(Byte.&toUnsignedInt).collect(Integer.&toHexString); break
    default: return
}

// Capture start time
final timerStart = Instant.now()

// Query providers in parallel threads
final threadPool = Executors.newFixedThreadPool(threads)
final List<LookupResult> listings
try {
    listings = providers.collect({ provider ->
        threadPool.submit({
            // Get the full host to query
            final host = (query + [provider]).join('.')

            // Start time measurement for specific DNS lookup
            final lookupTimerStart = Instant.now()

            // Try DNS lookup and filling up lookup result
            final listed
            try {
                switch (address) {
                    case Inet4Address: Inet4Address.getByName(host); break
                    case Inet6Address: Inet6Address.getByName(host); break
                }

                listed = true

            } catch (final UnknownHostException e) {
                listed = false
            }

            // Stop time measurement for specific DNS lookup
            final lookupTimerStop = Instant.now()

            return new LookupResult(
                    provider: provider,
                    listed: listed,
                    duration: Duration.between(lookupTimerStart, lookupTimerStop).toMillis(),
            )
        } as Callable<LookupResult>)
    }).collect({ future -> future.get() }).findAll({ result -> result.listed })

} finally {
    threadPool.shutdown()
    try {
        threadPool.awaitTermination(timeout, TimeUnit.MILLISECONDS)

    } catch (final InterruptedException) {
        if (!threadPool.isShutdown()) {
            threadPool.shutdownNow()
        }
    }
}

// Capture stop time
final timerStop = Instant.now()

// Record number of providers
times.put('providers', providers.size())

// Record number of listings
times.put('listings', listings.size())

// Record total duration
times.put('querytime', Duration.between(timerStart, timerStop).toMillis())

// Record state and reason
if (listings.empty) {
    results.put('status', 'OK')
} else {
    results.put('status', 'NOK')
    results.put('reason', 'Blacklisted on: ' + listings*.provider.join(', '))
}

println('times = ' + times)
println('results = ' + results)
