#!/usr/bin/perl
#
# This file is a part of alcanfw - A Linux Client Application+Netfilter FireWall.
#
# Copyright (C) 2013, Edward Fjellskål <edward.fjellskaal@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
######
# This was just something that has been up in my head for a long time.
# Some times Im super paranoid, and I just want to make sure the right
# stuff only talks on to the network. This is not as flexible and cool
# as I dreamt of, but rather a quick script made in 2-3h that will work
# at least for me for now.
#
# This probably wont work on a high traffic host, as this is written
# quick and dirty in an high level programming language... (perl).
# I might write it in C one day :)
#
# Install on Mr. Ubuntu 12.04.1 :
# $ apt-get install libnetpacket-perl libiptables-ipv4-ipqueue-perl
# $ sudo perl alcanfw.pl --verbose
#

use Getopt::Long qw/:config auto_help/;
use IPTables::IPv4::IPQueue qw(:constants);
use NetPacket::IP qw(IP_PROTO_UDP IP_PROTO_TCP);
use NetPacket::TCP;
use NetPacket::UDP;
use warnings;
use strict;

my $DEBUG = 0;
my $VERBOSE = 0;
my $FAST_PASS_VIA_NETFILTER = 0;
my $ALLOW_LOCAL_DNS = 0;

=head1 NAME

 alcanfw.pl - A Linux Client Application+Netfilter FireWall

=head1 VERSION

0.1

=head1 SYNOPSIS

 $ alcanfw.pl [options]

 OPTIONS:

 --daemon       : Not here yet!
 --debug        : enable debug messages
 --verbose      : makes it more verbose
 --fastpass     : Fast pass packets with conntrack (ESTABLISHED,RELATED)
 --localdns     : Allow local DNS lookups (DNS can be used as a covert channel!)
 --help         : this help message

=cut

GetOptions(
    'debug'       => \$DEBUG,
    'verbose'     => \$VERBOSE,
    'fastpass'    => \$FAST_PASS_VIA_NETFILTER,
    'localdns'    => \$ALLOW_LOCAL_DNS,
);

$VERBOSE = 1 if ($DEBUG == 1);

my $MEMVAL = 524280;

my $_user = (getpwuid $>);
die "[E] You need to be root!" if $_user ne 'root';

print "[*] Starting alcanfw version 0.1.22-beta7\n";
print "[*] Running with: debug=$DEBUG, verbose=$VERBOSE, fastpass=$FAST_PASS_VIA_NETFILTER, localdns=$ALLOW_LOCAL_DNS\n";

my $e;
print "[*] Tuning /proc/sys/net/core/[rw]mem_* values to $MEMVAL...\n"; 
$e = `echo $MEMVAL > /proc/sys/net/core/rmem_default`;
$e = `echo $MEMVAL > /proc/sys/net/core/rmem_max`;
$e = `echo $MEMVAL > /proc/sys/net/core/wmem_default`;
$e = `echo $MEMVAL > /proc/sys/net/core/wmem_max`;
print "[*] Setting up iptables queue...\n";
# $e = `iptables-restore < /etc/default/iptables-paranoid`;
# OR for quick test:
$e = `iptables -F`;
$e = `iptables -A INPUT -j ACCEPT`;
$e = `iptables -A OUTPUT -j ACCEPT`;
$e = `iptables -t mangle -F`;
# If we have accepted a connection, why not let netfilter pass them all after that?
# This saves lots of wasted userland cycles :)
if ($FAST_PASS_VIA_NETFILTER == 1) {
  $e = `iptables -t mangle -A OUTPUT -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT `;
}
if ($ALLOW_LOCAL_DNS == 1) {
  $e = `iptables -t mangle -A OUTPUT -p udp -s 127.0.0.1 -d 127.0.0.1 --dport 53 -j ACCEPT`
}
$e = `iptables -t mangle -A OUTPUT -p tcp -j QUEUE`;
$e = `iptables -t mangle -A OUTPUT -p udp -j QUEUE`;
#$e = ``;

# Signal handlers
use vars qw(%sources);
$SIG{"INT"}   = sub { cleaner() };
$SIG{"TERM"}  = sub { cleaner() };
$SIG{"QUIT"}  = sub { cleaner() };
$SIG{"KILL"}  = sub { cleaner() };

$^W = 1;
my $session = {};
use constant TIMEOUT => 1_000_000 * 2; # 2 seconds

sub cleaner {
  #$e = ``;
  print "\n[*] Flushing iptables rules...\n";
  # $e = `iptables-restore < /etc/default/iptables-I-had-my-medicine`;
  # OR for quick test:
  $e = `iptables -t mangle -F`;
  $e = `iptables -F`;
  clean_all_sessions();
  print "[*] Done\n";
  exit;
}

sub main {

  my ($queue, $msg);

  $queue = new IPTables::IPv4::IPQueue() or die IPTables::IPv4::IPQueue->errstr;
  $queue->set_mode( IPQ_COPY_PACKET, 1500 );

  print "[*] Processing packets from IPQueue!\n";
  while (1) {
    my $msg = $queue->get_message(TIMEOUT);
    if (!defined $msg) {
      next if IPTables::IPv4::IPQueue->errstr eq 'Timeout';
      die if IPTables::IPv4::IPQueue->errstr ne 'Timeout';
    }

    my $ret = "Err";
    my $pl    = $msg->payload();
    my $len   = $msg->data_len();
    my $ip    = NetPacket::IP->decode( $pl );
    my $ipsrc = $ip->{src_ip};
    my $ipdst = $ip->{dest_ip};
    my $ipsrcport = 0;
    my $ipdstport = 0;
    my $tcp;
    my $udp;
    my $key;

    if ($ip->{proto} == IP_PROTO_TCP) {
      print "[D] IP_PROTO_TCP ($ipsrc -> $ipdst)\n" if $DEBUG;
      $tcp         = NetPacket::TCP->decode( $ip->{data} );
      $ipsrcport   = $tcp->{src_port};
      $ipdstport   = $tcp->{dest_port};
      $key = "$ipsrc:$ipsrcport:$ipdst:$ipdstport";
      $session->{$ip->{proto}}->{$key}->{'lseen'} = time;
      if ( defined $session->{$ip->{proto}}->{$key}->{'access'} && $session->{$ip->{proto}}->{$key}->{'access'} == 1 ) {
        $queue->set_verdict($msg->packet_id(), NF_ACCEPT) > 0 or die IPTables::IPv4::IPQueue->errstr;
        print "[*] Fast Pass: $session->{$ip->{proto}}->{$key}->{'app'} $ipsrc:$ipsrcport -> $ipdst:$ipdstport (pid:$session->{$ip->{proto}}->{$key}->{'pid'})\n" if $VERBOSE;
        next;
      } elsif ( defined $session->{$ip->{proto}}->{$key}->{'access'} ) {
        print "[W] Fast Drop: $session->{$ip->{proto}}->{$key}->{'app'} $ipsrc:$ipsrcport -> $ipdst:$ipdstport (pid:$session->{$ip->{proto}}->{$key}->{'pid'})\n" if $VERBOSE;
        $queue->set_verdict($msg->packet_id(), NF_DROP) > 0 or die IPTables::IPv4::IPQueue->errstr;
        next;
      } else {
        # tcp        0      0 10.10.10.68:54133       74.125.136.18:443       ESTABLISHED 17479/firefox
        $ret = `netstat -pant|grep "^tcp .*$ipsrc:$ipsrcport.*$ipdst:$ipdstport"|awk '{print \$7}'`;
      }
    } elsif ($ip->{proto} == IP_PROTO_UDP) {
      print "[D] IP_PROTO_UDP ($ipsrc -> $ipdst)\n" if $DEBUG;
      $udp         = NetPacket::UDP->decode( $ip->{data} );
      $ipsrcport   = $udp->{src_port};
      $ipdstport   = $udp->{dest_port};
      $key = "$ipsrc:$ipsrcport:$ipdst:$ipdstport";
      $session->{$ip->{proto}}->{$key}->{'lseen'} = time;
      if ( defined $session->{$ip->{proto}}->{$key}->{'access'} && $session->{$ip->{proto}}->{$key}->{'access'} == 1 ) {
        $queue->set_verdict($msg->packet_id(), NF_ACCEPT) > 0 or die IPTables::IPv4::IPQueue->errstr;
        print "[*] Fast Pass: $session->{$ip->{proto}}->{$key}->{'app'} $ipsrc:$ipsrcport -> $ipdst:$ipdstport (pid:$session->{$ip->{proto}}->{$key}->{'pid'})\n" if $VERBOSE;
        next;
      } elsif ( defined $session->{$ip->{proto}}->{$key}->{'access'} ) {
        print "[W] Fast Drop: $session->{$ip->{proto}}->{$key}->{'app'} $ipsrc:$ipsrcport -> $ipdst:$ipdstport (pid:$session->{$ip->{proto}}->{$key}->{'pid'})\n" if $VERBOSE;
        $queue->set_verdict($msg->packet_id(), NF_DROP) > 0 or die IPTables::IPv4::IPQueue->errstr;
        next;
      } else {
        # udp        0      0 127.0.0.1:39218         10.10.10.1:53            ESTABLISHED 28982/nc
        $ret = `netstat -panu|grep "^udp .*$ipsrc:$ipsrcport.*$ipdst:$ipdstport"|awk '{print \$7}'`;
      }
    } else {
      print "[W] We should never be here if things are set up correct!\n";
      print "[W] But if we do get here, we just drop! And tell!\n";
      print "[D] IP_PROTO_UNKNOWN ($ipsrc -> $ipdst) - Dropping!\n";
      $queue->set_verdict($msg->packet_id(), NF_DROP) > 0 or die IPTables::IPv4::IPQueue->errstr;
      next;
    }

    my $pid   = "";
    my $sname = "";

    if ($ret =~ /^(-|)$/) {
       $pid = "-";
       $sname = "-";
    } elsif ($ret =~ /^(\d+)\/(.*)$/) {
       $pid = $1;
       $sname = $2;
    }

    my $rname;

    if ($pid =~ /^\d+$/) {
       $rname = `ls -alh /proc/$pid/exe |awk '{print \$11}'`;
       chomp $rname;
    } elsif ($sname =~ /\w+/) {
       $rname = $sname;
    } else {
       $rname = "Err";
    }

    # Whitelist goes here for now. This should be made a lot more advanced, like:
    #
    # policy->{"/usr/lib/firefox/firefox"}->{'allow_nets'} = "0.0.0.0/1,128.0.0.0/1";
    # policy->{"/usr/lib/firefox/firefox"}->{'allow_ports'} = "80,443";
    # policy->{"/usr/bin/ssh"}->{'allow_nets'} = "192.168.0.1/32";
    # policy->{"/usr/bin/ssh"}->{'allow_ports'} = "22";
    # and then decide from that
    #
    if ($rname =~ /^(\/usr\/lib\/firefox\/firefox|\/usr\/bin\/ssh)$/) {
        if ( ($ip->{proto} == IP_PROTO_TCP && ($ipdstport == 80 || $ipdstport == 22 || $ipdstport == 443)) || ($ipdstport == 53 && $ipdst eq "127.0.0.1" )) {
           print "[*] Accepting: $1 (pid:$pid) access to : $ip->{proto}:$ipdst:$ipdstport\n" if $VERBOSE;
           $queue->set_verdict($msg->packet_id(), NF_ACCEPT) > 0 or die IPTables::IPv4::IPQueue->errstr;
           $session->{$ip->{proto}}->{$key}->{'access'} = 1;
        } else {
           print "[W] Dropping : $rname (pid:$pid) access to : $ip->{proto}:$ipdst:$ipdstport\n";
           $queue->set_verdict($msg->packet_id(), NF_DROP) > 0 or die IPTables::IPv4::IPQueue->errstr;
           $session->{$ip->{proto}}->{$key}->{'access'} = 0;
        }
        $session->{$ip->{proto}}->{$key}->{'app'} = $rname;
        $session->{$ip->{proto}}->{$key}->{'pid'} = $pid;
    } elsif ($sname =~ /^(firefox|ssh)/ ) {
        if ( ($ip->{proto} == IP_PROTO_TCP && ($ipdstport == 80 || $ipdstport == 22 || $ipdstport == 443)) || ($ipdstport == 53 && $ipdst eq "127.0.0.1" )) {
           print "[*] Accepting: $1 (pid:$pid) access to : $ip->{proto}:$ipdst:$ipdstport\n" if $VERBOSE;
           $queue->set_verdict($msg->packet_id(), NF_ACCEPT) > 0 or die IPTables::IPv4::IPQueue->errstr;
           $session->{$ip->{proto}}->{$key}->{'access'} = 1;
        } else {
           print "[W] Dropping : $1 (pid:$pid) access to : $ip->{proto}:$ipdst:$ipdstport\n";
           $queue->set_verdict($msg->packet_id(), NF_DROP) > 0 or die IPTables::IPv4::IPQueue->errstr;
           $session->{$ip->{proto}}->{$key}->{'access'} = 0;
        }
        $session->{$ip->{proto}}->{$key}->{'app'} = $sname;
        $session->{$ip->{proto}}->{$key}->{'pid'} = $pid;
    } elsif ($ret =~ /^(-|)$/) {
        print "[*] Accepting: Closing/Dying Connection to : $ip->{proto}:$ipdst:$ipdstport\n" if $VERBOSE;
        $queue->set_verdict($msg->packet_id(), NF_ACCEPT) > 0 or die IPTables::IPv4::IPQueue->errstr;
        clean_old_sessions($ip->{proto});
    } elsif ($ret eq "Err") {
        print "[E] Dropping : $rname (pid:$pid) access to : $ip->{proto}:$ipdst:$ipdstport\n";
        $queue->set_verdict($msg->packet_id(), NF_DROP) > 0 or die IPTables::IPv4::IPQueue->errstr;
    } elsif ($ret =~ /^(.*)$/) {
        print "[W] Dropping : $rname (pid:$pid) access to : $ip->{proto}:$ipdst:$ipdstport\n";
        $queue->set_verdict($msg->packet_id(), NF_DROP) > 0 or die IPTables::IPv4::IPQueue->errstr;
        $session->{$ip->{proto}}->{$key}->{'access'} = 0;
        $session->{$ip->{proto}}->{$key}->{'app'} = $1;
        $session->{$ip->{proto}}->{$key}->{'pid'} = $pid;
    }
  }
}

sub clean_old_sessions {
   my $proto = shift;
   my $keys  = $session->{$proto};
   my $tnow  = time - 300; # Expire stuff after 5 minutes of idle
   foreach my $key (keys(%$keys)) {
      if (not defined $session->{$proto}->{$key}) {
         print "Not Defined\n" if $DEBUG;
         next;
      }

      if ( $session->{$proto}->{$key}->{'lseen'} < $tnow ) {
         if ($DEBUG) {
            print "[D] Deleting session: $key (";
            if (defined $session->{$proto}->{$key}->{'pid'}) {
               print "$session->{$proto}->{$key}->{'pid'} |";
            } else {
               print "- |";
            }
            if (defined $session->{$proto}->{$key}->{'app'}) {
               print " $session->{$proto}->{$key}->{'app'}";
            } else {
               print " -";
            }
            print ")\n";
         }
         delete($session->{$proto}->{$key});
      }
   }
}

sub clean_all_sessions {
   # Just to be nice :)
   print "[*] Deleting all sessions...\n";
   foreach my $proto (keys %$session) {
      my $keys  = $session->{$proto};
      foreach my $key (keys(%$keys)) {
          delete($session->{$proto}->{$key});
      }
   }
}

main();
