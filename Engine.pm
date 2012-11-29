package Engine;
#---------------------------------------------------------------------
# Engine - Forensic System Scanner Engine
# 
#
#
# created for ASI 
# Author: H. Carvey, keydet89@yahoo.com
#
# This software is released under the Perl Artistic License:
# http://dev.perl.org/licenses/artistic.html
#---------------------------------------------------------------------
use strict;
use Exporter;

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

$VERSION     = 0.1;
@ISA         = qw(Exporter);
@EXPORT      = ();
@EXPORT_OK   = qw(new);

use WinSetup;

# Global variables
# self reference
my $self = {};
my $win;				
my %sys = ();
my %plugins0; # hash-of-lists for system class plugins
my %plugins1; # hash-of-lists for user class plugins

#---------------------------------------------------------------------
# new()
# 
#---------------------------------------------------------------------      	    
sub new {
	my $class = shift;
	$win = WinSetup->new();
	return bless($self, $class);
}

#---------------------------------------------------------------------
# systemDir()
# 
#---------------------------------------------------------------------
sub systemDir {
	my $class = $_[0];
	if ($_[1] eq "") {
		return $self->{systemdir};
	}
	else {
# should end in system32		
		$self->{systemdir} = $_[1];
		$self->{systemdir} .= "\\" unless ($self->{systemdir} =~ m/\\$/);
		my @segs = split(/\\/,$self->{systemdir});
		my $num = scalar(@segs);
		$self->{drive} = join('\\',@segs[0..($num - 3)])."\\";
	}
}

#---------------------------------------------------------------------
# 
# 
#---------------------------------------------------------------------

#---------------------------------------------------------------------
# getSystemInfo ()
# 
#---------------------------------------------------------------------
sub getSystemInfo {
	my %hives = $win->setup($self->{systemdir});
	%sys = $win->getOSData();
	$sys{drive} = $self->{drive};
	
# Need to get SystemRoot path for the image, so it can be passed to the 
# plugins		
	my ($d,$w) = split(/\\/,$sys{"SystemRoot"},2);
	$sys{systemroot} = $sys{drive}.$w;
	$sys{systemroot} .= "\\" unless ($sys{systemroot} =~ m/\\$/);
	$self->{osflag} = $sys{osflag};
	return %sys;
}

sub getUserInfo {
	my %users = $win->getUserData();
	return %users;
}

#---------------------------------------------------------------------
# pluginsDir()
# Returns the plugins dir path
#---------------------------------------------------------------------
sub pluginsDir {
	my $class = $_[0];
	($_[1] eq "") ? (return $self->{plugindir}) : ($self->{plugindir} = $_[1]);
}

#---------------------------------------------------------------------
# sortPlugins()
# 
# Accesses the plugins dir to get a list of plugins 
# 1. Check OSMask value (osflag & osmask)
# 2. Generates (2) hashes-of-arrays, one for system class plugins, the
#    other for user class plugins
# 3. The keys of each hash are the categories.
# 4.  UI must then call the appropriate function to retrieve the
#     appropropriate hash
# 
#--------------------------------------------------------------------- 
sub sortPlugins {
	my $class = shift;
	my $output = shift || "report";
	my %plugins;
	
	%plugins0 = ();
	%plugins1 = ();
	
	my $cwd = Win32::GetCwd();
	$cwd .= "\\" unless ($cwd =~ m/\\$/);
	my $pluginsdir = $cwd."plugins\\";
	
	my @plugs;
	opendir(DIR,$pluginsdir);
	@plugs = grep {!/^\./ && m/\.pl$/} readdir(DIR);
	closedir(DIR);
	
	foreach my $p (@plugs) {
		eval {
			require $pluginsdir.$p;
			my $pkg = (split(/\./,$p,2))[0];
# Get the config information, create the list of plugins to run
			my $pluginconfig = $pkg->getConfig();
			
			if (($pluginconfig->{osmask} & $self->{osflag}) && ($pluginconfig->{"output"} =~ m/^$output/i)) {
				if ($pluginconfig->{class} == 0) {
					my @categories = split(/,/,$pluginconfig->{category});
					foreach my $c (@categories) {
						push(@{$plugins0{$c}},$pluginsdir.$p);	
					}
				}
				else {
					my @categories = split(/,/,$pluginconfig->{category});
					foreach my $c (@categories) {
						push(@{$plugins1{$c}},$pluginsdir.$p);	
					}
				}
			}
						
		};
		::logMsg("Engine Error: ".$@) if ($@);
	}
}
#----------------------------------------------------------------
# getSystemPlugins()
# returns the hash-of-lists of system plugins
#----------------------------------------------------------------
sub getSystemPlugins {
	return %plugins0;
}

#----------------------------------------------------------------
# getUserPlugins()
# returns the hash-of-lists of user plugins
#----------------------------------------------------------------
sub getUserPlugins {
	return %plugins1;
}

#----------------------------------------------------------------
# getError()
# returns the error message for the module
#----------------------------------------------------------------
sub getError {return $self->{error};}


1;
__END__

=head1 NAME

Name

=head1 SYNOPSIS

see example files

=head1 DESCRIPTION

Blah is a Perl module ...  

=head1 SEE ALSO



=head1 AUTHOR

Harlan Carvey, E<lt>keydet89@yahoo.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012

This library is free software; you can redistribute it and/or modify
it as you like.  However, please be sure to provide proper credit where
it is due.

=cut
