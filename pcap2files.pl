#!/home/foobar/perl5/perlbrew/perls/perl-5.18.4/bin/perl

use strict;
use warnings;
use NetPacket::Ethernet qw(:types);
use NetPacket::IP qw(:protos);
use NetPacket::TCP;
use Net::Pcap;
use Data::Dumper;
use IO::File;

my $pcap_file = shift(@ARGV);
my $workspace_root = shift(@ARGV);
my $err = undef;

die 'Usage: '.$0.' [pcapfile] [workspace]' if(!defined($pcap_file)) || !defined($workspace_root);
die 'Unable to open pcapfile '.$pcap_file if !(-f $pcap_file || -e $pcap_file || -r $pcap_file);

sub validate_workdir($) {
    $_ = shift;
    return(-e $_ || -d $_ || -w $_ || -r $_ || -x $_);
}

mkdir $workspace_root if !(-e $workspace_root);

die 'Unable to open/create workspace root '.$workspace_root if !validate_workdir($workspace_root);


my $_t = time();
my $workspace = $workspace_root.'/'.$_t;

die 'Temporary workspace '.$workspace.' already exists?' if -e $workspace;

mkdir $workspace;

die 'Unable to open/create workspace temp '.$workspace if !validate_workdir($workspace);

print 'Saving TCP Streams under '.$workspace."\n";

# TODO: Statistics about ongoing TCP Connections
my $statsTCP = {};

# Ad-hoc TCP Streams buffer constructors:
# $streamTCP = {}: {srcIp}{dstIp}{seqnum} = {'data' = undef/'', 'ack' = undef/seqnum}
my $streamsTCP = {};

# read data from pcap file.
my $pcap = pcap_open_offline($pcap_file, \$err)
    or die "Can't read $pcap_file : $err\n";
 #  loop over next 10 packets
pcap_loop($pcap, -1, \&process_packet, undef);

# close the device
pcap_close($pcap);

# 'src-port' || 'dest-port' -> streamsTCP reference
my $streamsTCPDirections = {};
my $streamSeq = 0;

sub register_tcpstream($$$$) {
    my ($src_ip, $dest_ip, $src_port, $dest_port) = (@_);

    $streamSeq++; # @GLOBAL
    my $newTCPStream =
    {'seq' => $streamSeq,
     'src_ip' => $src_ip, 'dest_ip' => $dest_ip,
     'src_port' => $src_port, 'dest_port' => $dest_port};

    $streamsTCP->{$src_ip}{$dest_ip}{$src_port}{$dest_port} = {};
#    my $newTCPStream = $streamsTCP->{$src_ip}{$dest_ip}{$src_port}{$dest_port};

    $streamsTCPDirections->{$src_ip}{$src_port}{$dest_ip}{$dest_port} = [1, $newTCPStream];
    $streamsTCPDirections->{$dest_ip}{$dest_port}{$src_ip}{$src_port} = [0, $newTCPStream];
    $streamsTCP->{$src_ip}{$dest_ip}{$src_port}{$dest_port} = $newTCPStream;

    print 'register_tcpstream = '.Data::Dumper::Dumper($streamsTCPDirections)."\n";

    return $newTCPStream;
}

sub figure_tcpstream($$$$) {
    my ($_ipa, $_ipb, $_porta, $_portb) = (@_);

#    print '_figure_tcpstream('.$_ipa.':'.$_porta.' - '.$_ipb.':'.$_portb.')'."\n";
#    print 'tcpstreams = '.Data::Dumper::Dumper($streamsTCPDirections)."\n";
    my @_streamReturn = @{$streamsTCPDirections->{$_ipa}{$_porta}{$_ipb}{$_portb}};
#    print '-> returning stream '.Data::Dumper::Dumper($_streamReturn)."\n";

    return @_streamReturn;
}

sub output_tcpstream($$) {
    my ($_workspace, $_streamHsh) = (@_);
    my $_bufdirs = '';

    if(!defined($_streamHsh->{data}) || keys(%{$_streamHsh->{data}})==0) {
	print STDERR 'No data to save. Skipping TCP Stream = '.Data::Dumper::Dumper($_streamHsh);
	return(0);
    }

#    foreach my $_add (qw/src_ip dest_ip src_port dest_port/) {
    foreach my $_add (qw/src_ip dest_ip/) {
	$_bufdirs .= '/'.$_streamHsh->{$_add};
	mkdir($workspace.'/'.$_bufdirs);
#	print 'Creating directory '.$_bufdirs."\n";
    }

#    print 'streamHsh to save: '.Data::Dumper::Dumper($_streamHsh)."\n";



    foreach my $_dataType (qw/0 1/) {
#	my $_outputFileName = $workspace.'/'.$_bufdirs.'/'.$_streamHsh->{seq}.'-'.($_dataType ? 'O' : 'T').'.tcp';
	my $_outputFileName = $workspace.'/'.$_bufdirs.'/'.$_streamHsh->{seq}.'-'.$_streamHsh->{'src_port'}.'_To_'.$_streamHsh->{'dest_port'}.'-'.($_dataType ? 'PEER' : 'HOST').'.tcp';

	print 'Output to '.$_outputFileName."\n";

	# Very Basic TCP Reassembly output based on seqNo iteration
	my $fh = IO::File->new(">".$_outputFileName);

	print 'This dataType<'.$_dataType.'> has sequences: '.join(',', keys %{$_streamHsh->{data}{$_dataType}})."\n";

	if (defined $fh) {
	    $fh->binmode;

	    my $_processedSeq = {};
	    for(my $_seqIteration=0;;$_seqIteration++) {
#		print "SeqItration ".$_seqIteration."\n";
		my @_seqDeletions = ();
		foreach my $_seqNo (sort {$a <=> $b} keys %{$_streamHsh->{data}{$_dataType}}) {

#		    print "seqNo<".$_seqNo.">: ".Data::Dumper::Dumper($_streamHsh->{data}{$_dataType}{$_seqNo})."\n";

		    my $_seq = $_streamHsh->{data}{$_dataType}{$_seqNo}[$_seqIteration];
		    my $_seqData = $_seq->[1];
#		    print $_seqIteration.' - '.$_seqNo.' was ack for '.$_seq->[0]."\n";

		    $fh->print($_seqData);

		    $_processedSeq->{$_seqNo}++;

#		    print "* seqNo<".$_seqNo."> processed: ".$_processedSeq->{$_seqNo}."\n";
#		    die;

		    
		    if(scalar(@{$_streamHsh->{data}{$_dataType}{$_seqNo}})==$_processedSeq->{$_seqNo}) {
			push(@_seqDeletions, $_seqNo);
		    }
		}

#		print "Iteration: ".$_seqIteration." End of seqs, Deletions: ".join(',', @_seqDeletions)."\n";

		foreach my $_seqDeletion (@_seqDeletions) {
		    $_streamHsh->{data}{$_dataType}{$_seqDeletion} = undef;
		    delete $_streamHsh->{data}{$_dataType}{$_seqDeletion};		    
		}

#		print Data::Dumper::Dumper($_streamHsh->{data}{$_dataType});
#		<STDIN>;
		last if(keys(%{$_streamHsh->{data}{$_dataType}})==0);
	    }
	    $fh->close;
	}

#	die;

    }

}

sub process_packet {
    my ($user_data, $header, $packet) = @_;

    my $ether_data = NetPacket::Ethernet::strip($packet);
    my $ip = NetPacket::IP->decode($ether_data);

    return 0 if $ip->{proto} != NetPacket::IP::IP_PROTO_TCP;

    my $tcp = NetPacket::TCP->decode($ip->{'data'});

#    print "ether_data = ".Data::Dumper::Dumper($ether_data)."\n";
#    print "IP = ".Data::Dumper::Dumper($ip)."\n";
#    print "TCP = ".Data::Dumper::Dumper($tcp)."\n";

    my $_p = 0;

    if($tcp->{flags} & NetPacket::TCP::SYN) {
	if($tcp->{flags} & NetPacket::TCP::ACK) {
	    print "SYN-ACK:\n";

#	    sub register_tcpstream($$$$) {
#		my ($src_ip, $dest_ip, $src_port, $dest_port) = (@_);
	    register_tcpstream($ip->{'dest_ip'}, $ip->{'src_ip'}, $tcp->{'dest_port'}, $tcp->{'src_port'});
	}
    }

    elsif(!($tcp->{flags} & NetPacket::TCP::SYN &&
	    $tcp->{flags} & NetPacket::TCP::RST)) {

#	print "TCP DATA = ".Data::Dumper::Dumper($tcp)."\n";

# $streamsTCP = {}: {srcIp}{dstIp}{seqnum} = ['data', 'ack' = \d+]

	my ($_isOrigin, $_streamHsh) =
	    figure_tcpstream($ip->{'src_ip'}, $ip->{'dest_ip'}, $tcp->{'src_port'}, $tcp->{'dest_port'});

#	print "We got ".$_isOrigin.' and streamHsh = '.$_streamHsh."\n";

	$_streamHsh->{pending}{$_isOrigin}{$tcp->{'seqnum'}} = [$tcp->{'acknum'}, $tcp->{'data'}];

        if($tcp->{flags} & NetPacket::TCP::ACK) {
#	    if(defined($streamHsh->{pending}{($_isOrigin ? 0 : 1)}{$tcp->{'seqnum'}
	    if(defined($_streamHsh->{pending}{$_isOrigin}{$tcp->{'seqnum'}})) {
#		print 'Confirmed seqnum<'.$tcp->{seqnum}.'>'."\n";
		if($_streamHsh->{pending}{$_isOrigin}{$tcp->{'seqnum'}}[1] ne '') {
		    push(@{$_streamHsh->{data}{$_isOrigin}{$tcp->{'seqnum'}}},
			 $_streamHsh->{pending}{$_isOrigin}{$tcp->{'seqnum'}});
		}
		$_streamHsh->{pending}{$_isOrigin}{$tcp->{'seqnum'}} = undef;
		delete $_streamHsh->{pending}{$_isOrigin}{$tcp->{'seqnum'}};
	    }
	    else {
		print 'MISSING PENDING FOR ACK.'."\n";
		$_streamHsh->{'acks'}{$_isOrigin}{$tcp->{'acknum'}} = $tcp->{'seqnum'};
	    }
	}

    }

    print "- ".
        $ip->{'src_ip'}, ":", $tcp->{'src_port'}, " -> ",
        $ip->{'dest_ip'}, ":", $tcp->{'dest_port'}, " S<".$tcp->{'seqnum'}."> A<".$tcp->{'acknum'}."> FLAGS: ".$tcp->{flags}." DataLen: ".bytes::length($tcp->{data})." ".($tcp->{flags} & ACK ? '*ACK*' : '')."\n";

#	print 'streamsTCP = '.Data::Dumper::Dumper($streamsTCP);

    if($tcp->{flags} & NetPacket::TCP::FIN) {
	print "FIN\n";

	my ($_isOrigin, $_streamHsh) =
	    figure_tcpstream($ip->{'src_ip'}, $ip->{'dest_ip'}, $tcp->{'src_port'}, $tcp->{'dest_port'});

	print 'Finished TCP Stream '.$_streamHsh->{'src_ip'}.':'.$_streamHsh->{'src_port'}.' -> '.$_streamHsh->{'dest_ip'}.':'.$_streamHsh->{'dest_port'}."\n";
	print 'Pending Packets:'."\n";
	print ' - By Origin: '.(keys %{$_streamHsh->{'pending'}{1}})."\n";
	print ' - By Target: '.(keys %{$_streamHsh->{'pending'}{0}})."\n";

	output_tcpstream($workspace, $_streamHsh);

	# KTODO
#	<STDIN>;
    }

    
#    <STDIN>;

}
