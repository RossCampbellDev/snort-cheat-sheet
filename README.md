# Snort Setup
`sudo apt-get install snort -y` obviously

`cd /etc/snort` to reach the configuration files

`ipvar HOME_NET any` -> change this to `ipvar HOME_NET xxx.xxx.xxx.xxx/xx` as appropriate

`include $RULE_PATH/custom.rules` -> to include a file containing our own hand made rules
commented out all of the default include lines to remove default rules for testing

add a test rule: `alert tcp any any -> $HOME_NET 21 (msg: "ftp conn"; sid: 1000001; rev:1;)`
*always use SID greater than 1 million to avoid conflicts with built in rules*

the above rule will look for TCP traffic from any source to any destination within $HOME_NET, on port 21.

`alert tcp any any -> $EXTERNAL_NET $HTTP_PORTS (msg:"went to bbc"; content: "bbc.co.uk"; nocase; sid:100003; rev:1;)`

the above rule looks for TCP traffic going out to the external network and going via any http ports (listed in snort.conf), where the packets contain the string "bbc.co.uk"

## Run snort
`snort -T -c /etc/snort/snort.conf`
-T -> Test
-c -> point to configuration

if it says it validated the configuration:

`snort -A console -q -c /etc/snort/snort.conf`
-A -> enables logging to console
-q -> less verbose

testing trying an ftp connection, and some icmp requests, we can now see alerts raised in the console

to run snort as a daemon and output to log:
`snort -D -c /etc/snort/snort.conf -l /var/log/snort/
