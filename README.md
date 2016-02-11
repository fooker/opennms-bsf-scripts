opennms-bsf-scripts
===================

Scripts for OpenNMS BSF monitors and detectors

Example poller-configuration.xml

    <service name="SPAM-Blacklist-Monitor" interval="7200000" user-defined="true" status="on">
      <parameter key="file-name" value="/etc/opennms/scripts/SpamBlackListMonitor.groovy"/>
      <parameter key="lang-class" value="groovy"/>
      <parameter key="bsf-engine" value="org.codehaus.groovy.bsf.GroovyEngine"/>
      <parameter key="run-type" value="exec" />
      <parameter key="retry" value="1" />
      <parameter key="timeout" value="60000" />
      <parameter key="timeout" value="60000" />
      <parameter key="threads" value="60000" />
      <parameter key="providers.v4" value="/path/to/my/dnsbl-providers-v4" />
      <parameter key="providers.v6" value="/path/to/my/dnsbl-providers-v6" />
      <parameter key="file-extensions" value="groovy,gy"/>
      <parameter key="rrd-repository" value="/opt/opennms/share/rrd/response"/>
      <parameter key="rrd-base-name" value="dnsrbl"/>
    </service>
    <monitor service="SPAM-Blacklist-Monitor" class-name="org.opennms.netmgt.poller.monitors.BSFMonitor"/>
    
