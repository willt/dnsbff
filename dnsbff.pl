#!/usr/bin/perl
#

$| = 1;
use strict;
use warnings;
use Data::Dumper;
use Getopt::Long;
use Net::Pcap qw(:functions);
use NetPacket::Ethernet qw(:strip :types);
use NetPacket::IP qw(:strip :protos :versions);
use NetPacket::TCP qw(:strip);
use NetPacket::UDP qw(:strip);
use Net::DNS::Packet;
use Net::DNS::Header;
use Net::DNS::RR;
use Net::IP qw(:PROC);
use Scalar::Util qw(reftype);
use Time::HiRes qw(gettimeofday tv_interval);
use Fcntl qw( :seek );
use POSIX ();
use List::MoreUtils qw(uniq);
use Sys::Syslog qw(:DEFAULT setlogsock);
setlogsock('unix');
$0 = "dnsbff";

####### Knobs  ##########################
my $WHITE_DOMAIN = "sonic\.net"; # Add your own domain. Don't really need this but it's extra safe so you don't blacklist your own domain.
my $DNS_IP = "208.201.224.33";   # Add your dns servers ip address
my $MIN_BLOCK_COUNT = 20; # 10 for testing
my $MAX_CACHE_TIME = 300;
my $MINDOTS = 3;
my $dev = 'eth0';
my $filter_str = "src host $DNS_IP and src port 53 and udp[11] & 8 = 0 and udp[11] & 4 = 0 and udp[11] & 2 = 2 and udp[11] & 1 = 0";
my $bad_zones_file = '/opt/bind/etc/named/bad-zones.conf';
my $cache_dump_file = "/tmp/dnsbff_cache_dump.txt";
my $MAX_CHECK_LOOP_COUNT = 100; # How often to check and add bad domains
my $MAX_CACHE_LOOP_COUNT = 500; # How often to clean cache
my $MIN_BLOCK_CLIENTS = 2; # Make sure we have at least this many unique clients
my $named_gid = 25;
my $check_conf = "/opt/bind/sbin/named-checkconf";
#########################################

my ($address, $netmask, $err, $filter);
my ($cache, $packet, $pcap);
my %header;
my $PIDFILE     = "/var/run/dnsbff";
my $PIDOPEN     = 0;
my $debug       = 0;
my $dry_run     = 0;
my $optimize    = 0;
my $cache_loops = 0;
my $check_loops = 0;

GetOptions( "debug" => \$debug,
            "dryrun" => \$dry_run ) || die "oops\n";

check_pidfile();
daemonize() unless $debug;

$SIG{QUIT} = sub { dump_cache(); }; # Sending SIG QUIT ( CTRL \ in debug mode) causes cache to be dumped to a file
$SIG{HUP} = sub { clean_cache(); }; # Here incase you want to trigger cache clean, maybe it should flush the cache instead?

if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
    die 'Unable to look up device information for ', $dev, ' - ', $err;
}

# open the device for live listening
$pcap = pcap_open_live($dev, 1500, 0, 0, \$err);
pcap_compile($pcap, \$filter, $filter_str, $optimize, $netmask) && die "Unable to compile filter";
Net::Pcap::setfilter($pcap, $filter) && die 'Unable to set packet capture filter';
#pcap_setnonblock($pcap, 0, \$err);

while (1)
{
    while (pcap_next_ex($pcap, \%header, \$packet))
    {
        process_packet("", \%header, $packet);
        $cache_loops++;
        $check_loops++;
        if ($cache_loops >= $MAX_CACHE_LOOP_COUNT)
        {
            $cache_loops = 0;
            clean_cache(); 
        }        

        if ($check_loops >= $MAX_CHECK_LOOP_COUNT)
	{
	    $check_loops = 0;
            check();
	}
    }
    logger("Failed to read packets from device. Will try again in 30 seconds.");
    sleep 30;
}
#Net::Pcap::pcap_close($pcap);


sub process_packet {
    my ( $user_data, $header, $packet ) = @_;

    my $dns;
    my $rec;
    my $len;
    my @seg_list;
    my $ip_obj = NetPacket::IP->decode(eth_strip($packet));

    if ( $ip_obj->{ver} == IP_VERSION_IPv4 ) {
        return unless ( $ip_obj->{proto} == IP_PROTO_UDP || $ip_obj->{proto} == IP_PROTO_TCP );

        $rec->{src_ip} = $ip_obj->{src_ip};
        $rec->{dst_ip} = $ip_obj->{dest_ip};

        if ( $ip_obj->{proto} == IP_PROTO_UDP ) {
            my $udp_obj = NetPacket::UDP->decode( $ip_obj->{data} );
            return unless $udp_obj;

            $rec->{src_port} = $udp_obj->{src_port};
            $rec->{dst_port} = $udp_obj->{dest_port};
            return unless ( $udp_obj->{data} );

            $dns = Net::DNS::Packet->new( \$udp_obj->{data} );
        }
        else {
            my $tcp_obj = NetPacket::TCP->decode( $ip_obj->{data} );
            return unless $tcp_obj;
            $rec->{src_port} = $tcp_obj->{src_port};
            $rec->{dst_port} = $tcp_obj->{dest_port};
            return unless ( $tcp_obj->{data} );
            $dns = Net::DNS::Packet->new( \$tcp_obj->{data} );
        }

        # don't have a valid dns packet
	return if !$dns;
        #unless ($dns) {
        #    return;
        #}

	my $client_ip = $rec->{dst_ip};
        my $header = $dns->header;
        my $rcode =  $header->rcode;

	# We only want SERVFAILS
	return if $rcode ne "SERVFAIL";
#	unless ($rcode eq "SERVFAIL")
#	{
#	    return;
#	}

        my ($question) = $dns->question;
	return if !$question;

        my $name  = $question->qname;
        my $type  = $question->qtype;
        my $class = $question->qclass;

        #if ( ($type eq "A") and ($rcode eq "SERVFAIL") )
	# only care about A records
        if ($type eq "A") 
        {
            my $ndots;
            ++$ndots while $name =~ m{\.}g;
            if ( $ndots && $ndots >= $MINDOTS) 
            {
                my $domain = lc $name;
		return if $domain =~ m/$WHITE_DOMAIN/;

                my @comp = split(/\./, $domain);
                my @host = split(/\./,$name);
                splice(@host, -3);
                my $host = join q{.}, @host;
                # host must be at least 7 characters and not more then 12
	        # must also be lowercase!
                if ( $host =~ m/^[a-z]{7,}$/ && $host !~ m/^[a-z]{12,}$/) {
                   logger("Adding $name to cache");
                    shift @comp if @comp > 2;
                    my $short = join q{.}, @comp;
                    my ($secs,$usec) = gettimeofday;

		    # update domain age
                    $cache->{$short}{age} = "$secs.$usec"; 

		    # Only increment domain counter if host is new
		    if (!exists($cache->{$short}{host}{$host}))
		    {
                        ++$cache->{$short}{count};
                    }
                    ++$cache->{$short}{host}{$host}{count};
                    $cache->{$short}{host}{$host}{age} = "$secs.$usec";
                    ++$cache->{$short}{host}{$host}{ip}{$client_ip};
                }
            }
        }
    }
}

sub check 
{
    my @baddies;
    #logger("Checking For Bad Domains") if $debug;
    for my $key (keys %{$cache})
    {
        # Don't look at individual hosts unless we have over X count
        if ($cache->{$key}{count} >= $MIN_BLOCK_COUNT)
        {
            my $host_count = keys %{$cache->{$key}{host}};
	    # check uniq clients
	    my @clients;
	    for my $hk (keys %{$cache->{$key}{host}})
	    {
		push @clients, keys %{$cache->{$key}{host}{$hk}{ip}};
            }
	    my $uniq_clients = uniq @clients;
            if ($host_count >= $MIN_BLOCK_COUNT && $uniq_clients >= $MIN_BLOCK_CLIENTS)
            {
                push @baddies, $key;
            }
        }
    }

    if (scalar(@baddies) > 0)
    {
        #logger(scalar(@baddies) . " Bad Domains found") if $debug;
       blacklist(\@baddies);
    }
}

sub clean_cache 
{
    #logger("Cleaning Cache:\n") if $debug;
    my $k_count = keys %{$cache};
    logger("CACHE: $k_count domains in cache");
    for my $key (keys %{$cache})
    {
        # Don't look at individual hosts unless we have over X count
        if ($cache->{$key}{count} >= $MIN_BLOCK_COUNT)
        {
            for my $host_key (keys %{$cache->{$key}{host}})
            {
                my ($secs,$usec) = split(/\./,$cache->{$key}{host}{$host_key}{age});
                if ( tv_interval( [$secs,$usec], [gettimeofday] ) > $MAX_CACHE_TIME )
                {
                    logger("HOST $host_key.$key expired");
                    --$cache->{$key}{count};
                    delete $cache->{$key}{host}{$host_key};
                }
            }
    
        }
        #Perhaps we aren't getting incremented. Check age of domain and expire if needed
        else 
        {
            my ($secs,$usec) = split(/\./,$cache->{$key}{age});
            if ( tv_interval( [$secs,$usec], [gettimeofday] ) > $MAX_CACHE_TIME )
            {
                logger("DOMAIN $key expired");
                delete $cache->{$key};
            }
        }

    }
}

sub dump_cache
{
    logger("Dumping cache to $cache_dump_file");
    if(open my $fh, '>', $cache_dump_file)
    {
        print $fh Dumper $cache;
        close $fh or die "Cannot close '$cache_dump_file': $!";
    } else {
        logger("Cannot read '$cache_dump_file' for writing: $!");
    }
}

sub blacklist {
    my ( $baddies ) = @_;

    my $now = POSIX::strftime( '%F %T', localtime );
    my @to_add;
    open my $fh, '<', $bad_zones_file or die "Cannot read '$bad_zones_file': $!";
    my $text = do { local $/; <$fh> };
    close $fh or die "Cannot close '$bad_zones_file': $!";

    my $new_zones;
  BAD_DOMAIN:
    for my $bad ( @$baddies ) {
        my $domains = keys %{$cache->{$bad}{host}};
        my $desc = "$cache->{$bad}{count} instances of $domains subdomains of $bad";
        if ( $text =~ m{^zone\s"$bad"\s*\{}xms ) {
            my $msg = "$bad already in $bad_zones_file: $desc";
            logger($msg);
            next BAD_DOMAIN;
        }
        else {
	    # check uniq clients
	    my @clients;
	    for my $hk (keys %{$cache->{$bad}{host}})
	    {
		push @clients, keys %{$cache->{$bad}{host}{$hk}{ip}};
            }
	    my $uniq_clients = uniq @clients;
	    my $uniq = " $uniq_clients unique clients";
            ++$new_zones;
            my $variant = $dry_run ? "DRY-RUN: OTHERWISE WOULD BLOCK '$bad'" : "BLOCKING '$bad'";
            my $message = "$variant: $desc";
	    logger($message);
            $text .= <<END;

// Found $desc $now $uniq
zone "$bad" {
    type master;
    file "/var/named/blank-zone";
    allow-query { 127.0.0.1; };
};
END
        }
    }

    #logger($text);

    return if not $new_zones;

    logger("BLACKLIST: $new_zones added");

    open $fh, '>', $bad_zones_file
        or die "Cannot read '$bad_zones_file' for writing: $!";
    print $fh $text;
    close $fh or die "Cannot close '$bad_zones_file': $!";

    chmod 0640, $bad_zones_file or die "Cannot chmod 0640 $bad_zones_file: $!";
    chown 0, $named_gid, $bad_zones_file
        or die "Cannot chown $bad_zones_file to 0, $named_gid: $!";

    my @cmd = ("$check_conf", "-t", "/opt/bind/chroot", "/etc/named/named.conf");
    system( @cmd ) == 0
        or die "@cmd failed: $?";

    @cmd = qw( rndc reconfig );
    system( @cmd ) == 0
        or die "@cmd failed: $?";

    return;
}

sub daemonize
{

        #open pidfile before forking.
        $PIDOPEN = open(FH, ">$PIDFILE") or die "Can't open pidfile $PIDFILE: $!";
        #$SIG{'INT'} = $SIG{'QUIT'} = $SIG{'TERM'} = \&remove_pidfile;
        $SIG{'INT'} = $SIG{'TERM'} = \&remove_pidfile;

        # Fork Child; parent dies.
        my $pid = fork;
        die "fork: $!" unless defined ($pid);
        if ($pid) { exit; }
        # Clean up environment.
        POSIX::setsid() or die "Can't start a new session: $!\n";
        chdir("/tmp");
        umask(0022);

        # Fork again to further cleanup any inherited attributes.
        $pid = fork;
        die "fork: $!" unless defined ($pid);
        if ($pid) { exit; }

        #write the PID out.
        print FH "$$\n";
        close(FH);

        # Close open file handles
        close (STDIN);
        close (STDOUT);
        close (STDERR);

        # Re-direct them so we don't leak any info.
        open(STDIN, '/dev/null');
        open(STDOUT, '>/dev/null');
        open(STDERR, '>/dev/null');
}

sub check_pidfile {
    if ( -e $PIDFILE ) {
        my $FH;
        open( $FH, "<$PIDFILE" );
        my $oldpid = readline($FH);
        close($FH);
        chomp $oldpid;
        if ( -d "/proc/$oldpid" ) {
            print STDERR "Error: already running as pid $oldpid\n";
            exit(1);
        }
    }
}

# Remove the pidfile and exit
sub remove_pidfile {
    return unless $PIDOPEN;
    unlink($PIDFILE);
    exit(0);
}

sub logger
{
    my $msg = shift;
    print "logmsg: $msg\n" if $debug;
    openlog($0,'cons,pid','local6');
    eval { syslog('info', '%s', $msg); };
    closelog();
    if ($@)
    {
        warn "syslog() failed ($msg) :: $@\n";
    }
}


sub logmsg
{
        my $msg = shift;
}
