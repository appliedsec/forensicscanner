package WinFile;
#---------------------------------------------------------------------
# WinFile.pm
# 
#
# Change history
#   20100922 - created
#
#
# References
#  
#
# copyright 2012 ASI
# This software is released under the Perl Artistic License:
# http://dev.perl.org/licenses/artistic.html
#---------------------------------------------------------------------
use strict;
use Exporter;
use Digest::MD5;

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

#---------------------------------------------------------------------
# new()
# 
#---------------------------------------------------------------------      	    
sub new {
	my $class = shift;
	return bless($self, $class);
}

#---------------------------------------------------------------------
# getMD5()
# Returns an MD5 hash
#--------------------------------------------------------------------- 
sub getMD5 {
	open(FH, $_[1]) or die "Can't open ".$_[1].": $!";
  binmode(FH);
  return Digest::MD5->new->addfile(*FH)->hexdigest();
}

#---------------------------------------------------------------------
# getSize()
# 
#--------------------------------------------------------------------- 
sub getSize {return (stat($_[1]))[7];}

#---------------------------------------------------------------------
# getFileExt()
# 
#--------------------------------------------------------------------- 
sub getFileExt {
# strip file name from path
	my @list = split(/\\/,$_[1]);
	my $i = scalar @list;
	my $file = $list[$i - 1];
	my @name = split(/\./,$file);
	my $sc = scalar @name;
	if ($sc == 2) {
		return $name[1];
	}
	elsif ($sc > 2) {
		return $name[$sc - 1];
	}
	else {
# something happened, or there is no file extension		
	}
	
}

#---------------------------------------------------------------------
# isMZSig()
# checks first two bytes for 'MZ' (0x5a4d)
#---------------------------------------------------------------------
sub isMZSig {
	my $data;
	open(FH,$_[1]);
	binmode(FH);
	seek(FH,0,0);
	read(FH,$data,2);
	if ($data eq "MZ") {
		return 1;
	}
	else {
		return 0;
	}
}


#----------------------------------------------------------------
# getError()
# returns the error message for the module
#----------------------------------------------------------------
sub getError {return $self->{error};}


1;
__END__

=head1 NAME

WinFile - Helper module for FSS Scanner

=head1 SYNOPSIS

see example files

=head1 DESCRIPTION

WinFile is a Perl module the provides helper functions for the main
driver component of the Forensic Scanner.  

=head1 SEE ALSO



=head1 AUTHOR

Harlan Carvey, E<lt>keydet89@yahoo.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Harlan Carvey (keydet89@yahoo.com)

This library is free software; you can redistribute it and/or modify
it as you like.  However, please be sure to provide proper credit where
it is due.

=cut
