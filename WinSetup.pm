package WinSetup;
#---------------------------------------------------------------------
# WinSetup.pm
# Helper package to collect data about the Windows OS from the Registry 
# hives
#
# Change history
#   20120813 - updated
#   20100926 - created
#
#
# References
#  Getting ProductType info to support the version
#    http://msdn.microsoft.com/en-us/library/ms724834%28VS.85%29.aspx
#
# copyright 2012 ASI
# Author: H. Carvey, keydet89@yahoo.com
# This software is released under the Perl Artistic License:
# http://dev.perl.org/licenses/artistic.html
#---------------------------------------------------------------------
use strict;
use Exporter;
use Parse::Win32Registry qw(:REG_);

# Included to permit compiling via Perl2Exe
#perl2exe_include "Parse/Win32Registry.pm";
#perl2exe_include "Parse/Win32Registry/Entry.pm";
#perl2exe_include "Parse/Win32Registry/Key.pm";
#perl2exe_include "Parse/Win32Registry/Value.pm";
#perl2exe_include "Parse/Win32Registry/File.pm";
#perl2exe_include "Parse/Win32Registry/Win95/File.pm";
#perl2exe_include "Parse/Win32Registry/Win95/Key.pm";
#perl2exe_include "Encode/Unicode.pm";

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

$VERSION     = 0.1;
@ISA         = qw(Exporter);
@EXPORT      = ();
@EXPORT_OK   = qw(new);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# Global variables
# self reference
my $self = {};				
my %systemhives = ();
my %userprofiles = ();

#---------------------------------------------------------------------
# new()
# 
#---------------------------------------------------------------------      	    
sub new {
	my $class = shift;
	return bless($self, $class);
}

#---------------------------------------------------------------------
# setup()
# 
#---------------------------------------------------------------------      	    
sub setup {
	my $class = shift;
	my $path = shift;
	
	$path .= "\\" unless ($path =~ m/\\$/);
	my @segs = split(/\\/,$path);
	my $num = scalar(@segs);
	$self->{drive} = join('\\',@segs[0..($num - 3)]);
	$self->{drive} .= "\\" unless ($self->{drive} =~ m/\\$/);
	
	my $hive_dir = $path."config";
	if (-e $hive_dir && -d $hive_dir) {
		if (-e $hive_dir."\\software" && -f $hive_dir."\\software") {
			my %guess = $self->getHiveType($hive_dir."\\software");
			foreach my $g (keys %guess) {
				if ($guess{"Software"} == 1) {
					$systemhives{software} = ($hive_dir."\\software");
					$self->{softwarehive} = ($hive_dir."\\software");
				}
			}
		}
		if (-e $hive_dir."\\system" && -f $hive_dir."\\system") {
			my %guess = $self->getHiveType($hive_dir."\\system");
			foreach my $g (keys %guess) {
				if ($guess{"System"} == 1) {
					$systemhives{system} = ($hive_dir."\\system");
					$self->{systemhive} = ($hive_dir."\\system");
				}
			}
		}
		if (-e $hive_dir."\\SAM" && -f $hive_dir."\\SAM") {
			my %guess = $self->getHiveType($hive_dir."\\SAM");
			foreach my $g (keys %guess) {
				if ($guess{"SAM"} == 1) {
					$systemhives{sam} = ($hive_dir."\\SAM");
					$self->{samhive} = ($hive_dir."\\SAM");
				}
			}
		}
		if (-e $hive_dir."\\security" && -f $hive_dir."\\security") {
			my %guess = $self->getHiveType($hive_dir."\\security");
			foreach my $g (keys %guess) {
				if ($guess{"Security"} == 1) {
					$systemhives{security} = ($hive_dir."\\security");
					$self->{securityhive} = ($hive_dir."\\security");
				}
			}
		}
		return %systemhives;
	}
	else {
		$self->{error} = "hive directory not found.";
		return 0;
	}
}

#---------------------------------------------------------------------
# getOSData()
# Get OS version information
#
# For CurrentVersion value:
#   http://msdn.microsoft.com/en-us/library/ms724832%28VS.85%29.aspx
#
#--------------------------------------------------------------------- 
sub getOSData {
	my %osdata;
	
	my %flag = ("5\.1" => 0x1,
	            "5\.2" => 0x2,
	            "6\.0" => 0x4, #Vista
	            "6\.1" => 0x10,
	            "6\.2" => 0x20);
	
	my $reg = Parse::Win32Registry->new($self->{softwarehive});
	my $root_key = $reg->get_root_key;
	if (my $key = $root_key->get_subkey("Microsoft\\Windows NT\\CurrentVersion")) {
# Reference for the CurrentVersion value:
# http://msdn.microsoft.com/en-us/library/ms724832%28v=vs.85%29.aspx
# if CV <= 5.2, 2003 or below; if CV > 5.2 (ie, 6.0, 6.1), Vista or above		
		my @vals = ("ProductName","CSDVersion","CurrentVersion","CurrentBuildNumber",
		            "InstallDate","CurrentType","SystemRoot");
		
		foreach my $v (@vals) {
			eval {
				$osdata{$v} = $key->get_value($v)->get_data();
				$osdata{$v} = gmtime($key->get_value($v)->get_data()) if ($v eq "InstallDate");
			};
		}
		$osdata{software} = $self->{softwarehive};
		$osdata{system}   = $self->{systemhive};
		$osdata{security} = $self->{securityhive};
		$osdata{sam}      = $self->{samhive};
		$osdata{computername} = getComputerName();
		$osdata{hostname} = getHostName();
		
		if (exists $flag{$osdata{"CurrentVersion"}}) {
			$osdata{osflag} = $flag{$osdata{"CurrentVersion"}};
		}
		else {
			$osdata{osflag} = 0xffff;
		}
		
		$self->{version} = $osdata{"CurrentVersion"};
		return %osdata;
	}
	else {
		return;
	}
}

#---------------------------------------------------------------------
# getUserData()
# 
# A ProfileList subkey is created for every user who logs onto a Windows
# system.
#--------------------------------------------------------------------- 
sub getUserData {
	my %paths;
	my $dirpath;
	
	if ($self->{version} >= 6.0) {
		$dirpath = $self->{drive}."Users\\";
	}
	else {
		$dirpath = $self->{drive}."Documents and Settings\\";
	}
	
	my @profiles;
	opendir(DIR,$dirpath);
	@profiles = readdir(DIR);
	closedir(DIR);
		
	foreach my $p (@profiles) {
		next if ($p =~ m/\./);
		$paths{$p} = $dirpath.$p;
	}
	 
	return %paths;
}

#---------------------------------------------------------------------
# getCurrentControlSet()
#
# gets the ControlSet marked as 'Current' from the System hive
#---------------------------------------------------------------------
sub getCurrentControlSet {
	my $reg = Parse::Win32Registry->new($self->{systemhive});
	my $root_key = $reg->get_root_key;
	my $key;
	
	eval {
		$key = $root_key->get_subkey("Select")->get_value("Current")->get_data();
		return $key;
	};
	return if ($@);
}

#---------------------------------------------------------------------
# getComputerName()
#--------------------------------------------------------------------- 
sub getComputerName {
	my $reg = Parse::Win32Registry->new($self->{systemhive});
	my $root_key = $reg->get_root_key;
	
	my $curr;
	eval {
		$curr = $root_key->get_subkey("Select")->get_value("Current")->get_data();
	};
	if ($@) {
#		print "Error: $@\n";
		return;
	}
	
	my $key_path = "ControlSet00".$curr."\\Control\\ComputerName\\ComputerName";
	if (my $key = $root_key->get_subkey($key_path)) {
		my $type;
		eval {
			$type = $key->get_value("ComputerName")->get_data();
		};
		if ($@) {
#			print "Error: $@\n";
			return;
		}
		else {
			return $type;
		}
	}
	else {
		return;
	}
}

#---------------------------------------------------------------------
# getTimeZoneInfo()
#--------------------------------------------------------------------- 
sub getTimeZoneInfo {
	my $reg = Parse::Win32Registry->new($self->{systemhive});
	my $root_key = $reg->get_root_key;
	my %tz;
	my $curr;
	eval {
		$curr = $root_key->get_subkey("Select")->get_value("Current")->get_data();
	};
	if ($@) {
#		print "Error: $@\n";
		return;
	}
	
	my $key_path = "ControlSet00".$curr."\\Control\\TimeZoneInformation";
	if (my $key = $root_key->get_subkey($key_path)) {
		my @vals = $key->get_list_of_values();
		if (scalar @vals > 0) {
			foreach my $v (@vals) {
				$tz{$v->get_name()} = $v->get_data();
			}
			return %tz;
		}
	}
	else {
		return;
	}
}

#---------------------------------------------------------------------
# getHostName()
#---------------------------------------------------------------------
sub getHostName {
	my $reg = Parse::Win32Registry->new($self->{systemhive});
	my $root_key = $reg->get_root_key;
	
	my $curr;
	eval {
		$curr = $root_key->get_subkey("Select")->get_value("Current")->get_data();
	};
	if ($@) {
#		print "Error: $@\n";
		return;
	}
	
	my $key_path = "ControlSet00".$curr."\\Services\\Tcpip\\Parameters";
	if (my $key = $root_key->get_subkey($key_path)) {
		my $type;
		eval {
			$type = $key->get_value("Hostname")->get_data();
		};
		if ($@) {
#			print "Error: $@\n";
			return;
		}
		else {
			return $type;
		}
	}
	else {
		return;
	}
	
	
}

#---------------------------------------------------------------------
# getProductType()
# 
# Get ProductType value
#--------------------------------------------------------------------- 
sub getProductType {
	my $reg = Parse::Win32Registry->new($self->{systemhive});
	my $root_key = $reg->get_root_key;
	
	my $curr;
	eval {
		$curr = $root_key->get_subkey("Select")->get_value("Current")->get_data();
	};
	if ($@) {
#		print "Error: $@\n";
		return;
	}
	
	my $key_path = "ControlSet00".$curr."\\Control\\ProductOptions";
	if (my $key = $root_key->get_subkey($key_path)) {
		my $type;
		eval {
			$type = $key->get_value("ProductType")->get_data();
		};
		if ($@) {
#			print "Error: $@\n";
			return;
		}
		else {
			return $type;
		}
	}
	else {
		return;
	}
}

#---------------------------------------------------------------------
# is64bit()
# boolean
#--------------------------------------------------------------------- 
sub is64bit {
	my $reg = Parse::Win32Registry->new($self->{softwarehive});
	my $root_key = $reg->get_root_key;
	if ($root_key->get_subkey("WOW6432Node")) {
		return 1;
	}
	else {
		return 0;
	}
}

#---------------------------------------------------------------------
# getHiveType()
# Attempts to guess the type of hive; NTUSER, SAM, Security, System, Software
# If the hive is NTUSER, attempts to get the SID and "logon user name"
# If the hive is System, attempts to get the ComputerName value
#--------------------------------------------------------------------- 
sub getHiveType {
	my $class = shift;
	my $hive = shift;
	
	my $reg;
	my $root_key;
	my %guess;
	
	eval {
		$reg = Parse::Win32Registry->new($hive);
	  $root_key = $reg->get_root_key;
	};
	
# Check for SAM
	eval {
		$guess{SAM} = 1 if (my $key = $root_key->get_subkey("SAM\\Domains\\Account\\Users"));
	};
# Check for Software	
	eval {
		$guess{Software} = 1 if ($root_key->get_subkey("Microsoft\\Windows\\CurrentVersion") &&
				$root_key->get_subkey("Microsoft\\Windows NT\\CurrentVersion"));
	};

# Check for System	
	eval {
		$guess{ucfirst "system"} = 1 if ($root_key->get_subkey("MountedDevices") &&
				$root_key->get_subkey("Select"));
	};
	
	if ($guess{ucfirst "system"} == 1) {
		eval {
			my $control = $root_key->get_subkey("Select")->get_value("Current")->get_data();
			$guess{compname} = $root_key->get_subkey("ControlSet00".$control."\\Control\\ComputerName\\ComputerName")
			                   ->get_value("ComputerName")->get_data();
		};
	}
	
# Check for Security	
	eval {
		$guess{Security} = 1 if ($root_key->get_subkey("Policy\\Accounts") &&
				$root_key->get_subkey("Policy\\PolAdtEv"));
	};
# Check for NTUSER.DAT
# if it is an NTUSER.DAT hive, attempt to determine the SID and logon user name	
	eval {
		$guess{NTUSER} = 1 if ($root_key->get_subkey("Software\\Microsoft\\Windows\\CurrentVersion"));
	};	
	
	if ($guess{NTUSER} == 1) {
		my @sids;
		eval {
	 		my @subkeys = $root_key->get_subkey("Software\\Microsoft\\Protected Storage System Provider")->get_list_of_subkeys();
	 		map{push(@sids,$_->get_name())}@subkeys;
	 	};
#	 	die "Error attempting to locate SID: $!\n" if ($@);
	 	$guess{sid} = $sids[0] if (scalar(@sids) == 1);
	 	
	 	eval {
	 		$guess{username} = $root_key->get_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer")
	 		           ->get_value("Logon User Name")->get_data();		
		};
	}
	
	eval {
		$guess{USRCLASS} = 1 if ($root_key->get_subkey("CLSID") && $root_key->get_subkey("LocalSettings")
		                         && $root_key->get_subkey("Interface"));
	};
	
	return %guess;
}
#----------------------------------------------------------------
# getError()
# returns the error message for the module
#----------------------------------------------------------------
sub getError {return $self->{error};}


1;
__END__

=head1 NAME

WinSetup - Helper package for Scanner

=head1 SYNOPSIS

see example files

=head1 DESCRIPTION

WinSetup is a Perl module the provides helper functions for the main
driver component of the scanner.  Data is returned to the main driver
component so that decisions can be made.  

=head1 SEE ALSO



=head1 AUTHOR

Harlan Carvey, E<lt>keydet89@yahoo.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Harlan Carvey (keydet89@yahoo.com)

This library is free software; you can redistribute it and/or modify
it as you like.  However, please be sure to provide proper credit where
it is due.

=cut
