#!/usr/bin/perl
#
# ClipCast 1.0
# Copyright (C) 2010 by Alessandro Zummo <a.zummo@towertech.it>
# All Rights Reserved
#
# Licensed under GPLv2


use strict;
use warnings;
use utf8;

package ClipCast;

use Crypt::CBC;
use Digest::MD5 qw(md5);

use base 'Class::Accessor';

__PACKAGE__->mk_accessors(qw( pass addr port last debug minlen ));

sub inbound
{
	my ($self, $socket) = @_;

	my $data;
	$socket->recv($data, 1024);

	my ($clip, $type) = decode($self->pass, $data);
	return (undef, 0) unless defined $clip;
	return (undef, 0) unless length($clip) >= $self->minlen;

	$self->last($clip)
		if defined $clip;

	printf("RX (%d) %3d: %s\n", $type, length($clip), $clip)
		if $self->debug;

	return ($clip, $type);
}

sub outbound
{
	my ($self, $socket, $type, $data) = @_;

	return unless defined $data;
	return unless length($data) >= $self->minlen;
	return if $data eq $self->last;

	$self->last($data);
	
	my $packet = pack('C C xxxx a16 a*', 0xCC, $type, md5($data), $data);

	printf("TX (%d) %3d: %s\n", $type, length($data), $data)
		if $self->debug;

	$socket->mcast_send(encode($self->pass, $packet),
		$self->addr . ':' . $self->port);
}

sub encode
{
	my ($pass, $data) = @_;

	my $salt = Crypt::CBC->random_bytes(8);
	my $key = md5($pass . $salt);
	my $iv = md5($key . $pass . $salt);

	my $cipher = Crypt::CBC->new(
		'-key'	  	=> $key,
		'-keysize'      => 16,
		'-literal_key'  => 1,
		'-cipher'       => 'Crypt::Rijndael',
		'-iv'		=> $iv,
		'-header'       => 'none',
	);

	return $salt . $cipher->encrypt($data);
}

sub decode
{
	my ($pass, $data) = @_;

	my $salt = substr($data, 0, 8);
	$data = substr($data, 8);

	my $key = md5($pass . $salt);
	my $iv = md5($key . $pass . $salt);

	my $cipher = Crypt::CBC->new(
		'-key'		=> $key,
		'-keysize'      => 16,  
		'-literal_key'  => 1,   
		'-cipher'       => 'Crypt::Rijndael',
		'-iv'		=> $iv,
		'-header'       => 'none',
	);

	$data = $cipher->decrypt($data);
	return undef
		unless defined $data;

	my ($header, $type, $sum, $clip) = unpack('C C x4 a16 a*', $data);

#	print length($header), "\n";
#	print length($sum), "\n";
#	print length($clip), "\n";

	return undef
		unless $header == 0xCC;

	return undef
		unless $sum eq md5($clip);

	return ($clip, $type);
}

1;


package ClipCast::Linux;

use base 'Class::Accessor';

__PACKAGE__->mk_accessors(qw( cc ));

eval {
	require Gtk2;
	require Gtk2::Helper;
};

sub loop
{
	my ($self, $socket) = @_;

	Gtk2->init;
	
	my $clipboard = Gtk2::Clipboard->get(Gtk2::Gdk->SELECTION_CLIPBOARD);
	my $primary = Gtk2::Clipboard->get(Gtk2::Gdk->SELECTION_PRIMARY);

	# inbound clipboard
	Gtk2::Helper->add_watch($socket->fileno, 'in' => sub {

		my ($clip, $type) = $self->cc->inbound($socket);
		return 1 unless $clip;

		$clipboard->set_text($clip) if $type == 0x01;
		$primary->set_text($clip) if $type == 0x02;

		return 1;
	});

	# outbound clipboard
	$clipboard->signal_connect('owner-change' => sub {

		my $data = $clipboard->wait_for_text;
		$self->cc->outbound($socket, 0x01, $data);
	});

	$primary->signal_connect('owner-change' => sub {

		my $data = $primary->wait_for_text;
		$self->cc->outbound($socket, 0x02, $data);
	});

	Gtk2->main;
}


package ClipCast::Darwin;

use base 'Class::Accessor';

__PACKAGE__->mk_accessors(qw( cc ));

eval {
	require Mac::Pasteboard;
};

sub loop
{
	my ($self, $socket) = @_;

	my $pb = new Mac::Pasteboard;

	# inbound only
	while (1) {
		my ($clip, $type) = $self->cc->inbound($socket);
		if (defined $clip) {
			$pb->clear;
			$pb->copy($clip);
		}
	}
}

1;


package main;

use IO::Socket::Multicast;

	my $pass = shift @ARGV
		or die "usage: $0 <password>\n";

	my $addr = '226.1.1.123';
	my $port = 9123;

	# init multicast socket

	my $s = IO::Socket::Multicast->new(
		'LocalPort'	=> $port,
		'ReuseAddr'	=> 1,
	) or die;

	$s->mcast_add($addr);
	$s->mcast_loopback(0);


	print "ClipCast running with multicast group $addr and port $port\n";

	my $cc = ClipCast->new({ 'pass' => $pass, 'addr' => $addr,
		'port' => $port, 'last' => '', 'debug' => 1, 'minlen' => 4 });

	if ($^O eq 'linux') {

		ClipCast::Linux->new({ 'cc' => $cc })->loop($s);

	} elsif ($^O eq 'darwin') {

		ClipCast::Darwin->new({ 'cc' => $cc })->loop($s);

	} else {

		print "unsupported os: $^O\n";
	}

