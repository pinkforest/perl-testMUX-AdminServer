#!/usr/bin/perl

package AdminStack;

use strict;
use warnings;

use POSIX;
#use IO::Socket::INET;
use Socket;
use POSIX;
use Data::Dumper;
use bytes;
use BSON;

require Exporter;

my @ISA = qw(Exporter);
my @EXPORT = qw();

use constant {

    DEBUG_LVL       => 0x00,
    DEBUG_FNC       => 0x01,
    OBJ_TMUX        => 0x02,
    SELF_ID         => 0x03,
    MAP_OPTS        => 0x04,
    AUTH_TYPE       => 0x05,

     A_TYPE_MONGO   => 0x01,

    AUTH_HOST       => 0x06,
    AUTH_PORT       => 0x07,
    C_AUTH_M        => 0x08,
    C_AUTH_D        => 0x09,

     A_IDX_STATE    => 0x01,

      A_STATE_IDLE  => 0x01,
      A_STATE_RUN   => 0x02,

     A_IDX_RETRS    => 0x02,
     A_IDX_START    => 0x03,

    ######### DATA index PART - START
    #

    T_INBUF_LEN   => 0x01,
    T_INBUF_DATA  => 0x02,
    T_OUTBUF_LEN  => 0x03,
    T_OUTBUF_DATA => 0x04,

    # Cached peer info (ref may be gone)
    T_PEER_I      => 0x05,

     I_PEER_ADDR    => 0x01,
     I_PEER_PORT    => 0x02,
     I_PEER_OBJ     => 0x03,
    
    # Cached server info (ref may be gone)
    T_SERVER_I    => 0x06,

     I_SERVER_ADDR  => 0x01,
     I_SERVER_PORT  => 0x02,
     I_SERVER_OBJ   => 0x03,
    
    T_SEPR_CHAR     => 0x07,
    #
    ######### DATA index PART - END

    D_DEBUG       => 1,

    CRLF => "\r\n"
};


sub __debug($$) {
    my $self = shift;

    return if !ref($self->[DEBUG_FNC]);

    $self->[DEBUG_FNC](@_);

}

# @slow
sub t_fmt_ascii($) {
    return ( join("", map { $_ = ord(); ( $_>126 || $_<32 ? sprintf("<%02X>",$_) : chr() ) } split("",shift)) );
}

sub _closeClient($$;$) {
    my ($self, $_fno, $err) = (@_);
    $self->__debug(5,$_fno, 'Client closed TCP Connection'.(defined($err)?': '.$err:''));

    $self->[OBJ_TMUX]->del($_fno);

}

sub _sendClient($$$) {
    my ($self, $_fno, $_data) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    my $_olen = bytes::length($_data);

    $self->__debug(5,$_fno, __PACKAGE__.':'.__LINE__.'-_sendClient() bytes<'.$_olen.'> data<'.t_fmt_ascii($_data).'>');

    if ( $_olen > 0 ) {

	$_d->[T_OUTBUF_DATA] .= $_data;
	$_d->[T_OUTBUF_LEN]  += $_olen;

	$self->[OBJ_TMUX]->mOUT($_fno, 1);

    }

    return($_olen);
}

sub myID($;$) {
    my ($self, $_id) = (@_);

    if ( defined ( $_id ) ) {
        $self->[SELF_ID] = $_id;
    }

    return($self->[SELF_ID]);
}

sub hookTCPListener($$) {
    my ($self, $_nfd, $_fno) = (@_);
    $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]] = [];
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $self->__debug(5,$_fno, __PACKAGE__.':'.__LINE__.'-_hookTCPListener('.$_fno.') myID = '.$self->[SELF_ID]);
    
    $_d->[T_SERVER_I] = [];
    $_d->[T_SERVER_I][I_SERVER_OBJ] = $_nfd;
#    $_d->[T_SERVER] = 1;
}

##########################
# MtikClient Callbacks
#

sub __callback_mtik_connect($$$$) {
    my ($self, $_fno, $_o_fno, $_code, $_data) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $self->_sendClient($_fno, '__callback_mtik_connect('.$_fno.', '.$_o_fno.', '.$_code.', '.$_data.')'. CRLF);

    if ( $_code == 0 ) {
	$self->[OBJ_TMUX]->adopt($_fno, $_o_fno, $self, '__callback_mtik_login');
    }
}

sub __callback_mtik_login($$$$) {
    my ($self, $_fno, $_o_fno, $_code, $_data) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $self->_sendClient($_fno, '__callback_mtik_login('.$_fno.', '.$_o_fno.', '.$_code.', '.$_data.')'. CRLF);

    if ( $_code == 0 && $_data =~ /^OK/ ) {
	$self->[OBJ_TMUX]->adopt($_fno, $_o_fno, $self, '__callback_mtik_idle');
    }
}

sub __callback_mtik_idle($$$$) {
    my ($self, $_fno, $_o_fno, $_code, $_data) = (@_);

    $self->_sendClient($_fno, '__callback_mtik_idle('.$_fno.', '.$_o_fno.', '.$_code.', '.$_data.')'. CRLF);

}

sub __callback_mongo($$$$) {
    my ($self, $_fno, $_o_fno, $_code, $_data) = (@_);

    $self->_sendClient($_fno, '__callback_mongo('.$_fno.', '.$_o_fno.', '.$_code.', '.Dumper($_data).')'. CRLF);
}

#
########### Authenticator Callbacks
#

sub __callback_auth_mongo_connect($$$$) {
    my ($self, $_fno, $_o_fno, $_code, $_data) = (@_);

    if ( defined ( $self->[C_AUTH_M]{$_o_fno} ) ) {

	if ( $_code == 0 && $_data =~ /^OK/ ) {
	    $self->__debug(5, 0, '__callback_auth_mongo_connect('.$_fno.', '.$_o_fno.', '.$_code.') Connect OK For Authenticator<'.$self->[C_AUTH_M]{$_o_fno}.'>');
	    $self->[OBJ_TMUX]->adopt(0, $_o_fno, $self, '__callback_auth_mongo_idle');
	}
    }
    else {
	$self->__debug(5, $_fno, '/*** BUG='.__PACKAGE__.':'.__LINE__.'-__callback_auth_mongo_connect WAS not marked as authenticator _o_fno = '.$_o_fno.', code='.t_fmt_ascii($_code).',_data='.t_fmt_ascii($_data));
    }
}

#
##########################

sub __auth_handler_dispatch($$$$) {
    my ($self, $_fno, $_u, $_p) = (@_);

    foreach my $_c_fno ( keys %{$self->[C_AUTH_M]} ) {
	my $_aid = $self->[C_AUTH_M]{$_c_fno};
	if ( $self->[C_AUTH_D][$_aid][A_IDX_STATE] == A_STATE_IDLE ) {
	    $self->[C_AUTH_D][$_aid][A_IDX_STATE] = A_STATE_RUN;

	    
	    $self->[OBJ_TMUX]->mTimeout(10, $_c_fno, $self, '__auth_timeout');
	    $self->[C_AUTH_D][$_aid][A_IDX_START] = time();
	    $self->[C_AUTH_D][$_aid][A_IDX_RETRS] = 0;
	}
    }
}

sub __callback_auth_mongo_error($$$$$) {
    my ($self, $_fno, $_o_fno, $code, $data) = (@_);
}

sub __callback_auth_mongo_timeout($$$$$) {
    my ($self, $_fno, $_o_fno, $_code, $_data) = (@_);

}

sub _process($$) {
    my ($self, $_fno) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    my $zz = 0;

    $self->__debug(5,$_fno, __PACKAGE__.':'.__LINE__.'-_process() bytes<'.$_d->[T_INBUF_LEN].'> data<'.t_fmt_ascii($_d->[T_INBUF_DATA]).'>');

    foreach my $cmd (split("\n", $_d->[T_INBUF_DATA])) {
        $cmd=~s/\r//g;
	$zz++;

	if ( $cmd =~ /^separator\s*(.*)$/ ) {
	    my $_c = $1;
	    if ( defined ( $_c ) && bytes::length($_c) == 1 ) {
		$_d->[T_SEPR_CHAR] = $_c;
	    }
	    $self->_sendClient($_fno,'SEPARATOR='.t_fmt_ascii($_d->[T_SEPR_CHAR]). CRLF);
	}
	elsif ( $cmd =~ /^create MTikClient (\d+\.\d+\.\d+\.\d+):(\d+)\s*(.*)$/o ) {
	    my ($_host, $_port, $_t) = ($1, $2, $3);

	    my $_nfno = $self->[OBJ_TMUX]->addTCPConnector('MTikClient', $_host, $_port);

	    if ( defined ( $_nfno ) && $_nfno > 0 ) {
		$self->[OBJ_TMUX]->adopt($_fno, $_nfno, $self, '__callback_mtik_connect');

		if ( $_t =~ /^user=([A-Za-z0-9]+) password=(.+)$/o ) {
		    my ($_u, $_p) = ($1, $2);
		    my $_mtikStack = $self->[OBJ_TMUX]->getHandlerObj_key('MTikClient');
		    $_mtikStack->login($_nfno, $_u, $_p);
		}
	    }
	    else {
		$self->_sendClient($_fno,'Error with MTikClient ... '. CRLF);
	    }
	}

	elsif ( $cmd =~ /^create TMongoClient (\d+\.\d+\.\d+\.\d+):(\d+)\s*(.*)$/o ) {
	    my ($_host, $_port, $_t) = ($1, $2, $3);

	    my $_nfno = $self->[OBJ_TMUX]->addTCPConnector('TMongoClient', $_host, $_port);

	    if ( defined ( $_nfno ) && $_nfno > 0 ) {
		$self->[OBJ_TMUX]->adopt($_fno, $_nfno, $self, '__callback_mongo');

		if ( $_t =~ /^user=([A-Za-z0-9]+) password=(.+)$/o ) {
		    my ($_u, $_p) = ($1, $2);
		    my $_mongoStack = $self->[OBJ_TMUX]->getHandlerObj_key('TMongoClient');
		    $_mongoStack->login($_nfno, $_u, $_p);
		}
	    }
	    else {
		$self->_sendClient($_fno,'Error with TMongoClient ... '. CRLF);
	    }
	}

	elsif ( $cmd =~ /^MTikClient (\d+) (.+)/o ) {
	    my ($_mtik, $str) = ($1, $2);

	    my $_mtikStack = $self->[OBJ_TMUX]->getHandlerObj_key('MTikClient');
	    my $_mtikId = $_mtikStack->myID();

	    if ( defined ( $self->[OBJ_TMUX][$_mtik][$_mtikId] ) ) {

		if ( $str =~ /^login user=([A-Za-z0-9\-_:]+) password=(.+)$/ ) {
		    my ($_u, $_p) = ($1, $2);
		    $_mtikStack->login($_mtik, $_u, $_p);
		    $self->[OBJ_TMUX]->adopt($_fno, $_mtik, $self, '__callback_mtik_login');
		}

		if ( $str =~ /^(\/.+)$/o ) {
		    my ($str) = ($1);
		    $_mtikStack->_sendMtik($_mtik, [[split " ", $str]]);
		}

	    }
	}

	elsif ( $cmd =~ /^TMongoClient (\d+) (.+)/o ) {
	    my ($_mongo, $str) = ($1, $2);

	    my $_mongoStack = $self->[OBJ_TMUX]->getHandlerObj_key('TMongoClient');
	    my $_mongoId    = $_mongoStack->myID();

	    if ( defined ( $self->[OBJ_TMUX][$_mongo][$_mongoId] ) ) {

		if ( $str =~ /^insert ([a-zA-Z0-9\.]+) (.+)/o ) {
		    my ($col, $kvp_l) = ($1, $2);
		    my $doco = {};

		    foreach my $_kvp ( split(/,/o, $kvp_l) ) {
			if ( $_kvp =~ /^(.+[^\\])=(.+)$/o ) {
			    my ($_k, $_v) = ($1, $2);
			    $_v =~ s/\s+$//;
			    $doco->{$_k} = $_v;
			}
		    }

		    $_mongoStack->m_insert($_mongo, 0, $col, [$doco] )
			if scalar(keys %{$doco});
		}
		elsif ( $str =~ /^select\s([a-zA-Z0-9\.]+)\s*(.*)$/o) {
		    my ($col, $kvp_l) = ($1, $2);
		    my $doco = {};

		    foreach my $_kvp ( split(/[,\2]/o, $kvp_l) ) {
			if ( $_kvp =~ /^(.+[^\\])=(.+)$/o ) {
			    my ($_k, $_v) = ($1, $2);
			    $_v =~ s/\s+$//;
			    $doco->{$_k} = $_v;
			}
		    }

		    $_mongoStack->m_query($_mongo, 0x20, $col, 
					  0, 0, $doco);

		}
		elsif ( $str =~ /^remove\s([A-Za-z0-9\.]+)\s(.+)$/o ) {
		    my ($col, $kvp_l) = ($1, $2);
		    my $doco = {};

		    foreach my $_kvp ( split(/,/o, $kvp_l) ) {
			if ( $_kvp =~ /^(.+[^\\])=(.+)$/o ) {
			    my ($_k, $_v) = ($1, $2);
			    $_v =~ s/\s+$//;
			    $doco->{$_k} = $_v;
			}
		    }

		    $_mongoStack->m_remove($_mongo, 0, $col, $doco )
			if scalar(keys %{$doco});
		}

	    }
	}

	elsif ( $cmd =~ /^PING (\d+)$/oi ) {
	    my $_i = $1;
	    $self->_sendClient($_fno,'PONG '.$_i.CRLF);
	}
	elsif ( $cmd =~ /^nick (\d+) ([A-Za-z0-9\Q.:-_+=@\E]+)$/o ) {
	    my ($_id, $_n) = ($1, $2);
	    if ( defined ( $self->[OBJ_TMUX][$_id] ) ) {
		$self->[OBJ_TMUX]->mNick($_id, $_n);
	    }
	}
	elsif ( $cmd =~ /^nicks/o ) {
	    my $_bs = $self->[OBJ_TMUX]->nicks();

	    if ( ! defined ( $_bs ) || !scalar(keys %{$_bs}) ) {
		$self->_sendClient($_fno,'0 NICKS'. CRLF);
	    }
	    else {
                my ($_out, $_c);
                foreach my $_nick (keys %{$_bs}) {
                    $_c++;
                    $_out .= 'NICK '.$_bs->{$_nick}.' '.$_nick.
			CRLF;
                }
                $self->_sendClient($_fno, $_c.' NICKS'. CRLF. $_out);
	    }
	}
	elsif ( $cmd =~ /^tmux dump$/o ) {
	    $self->_sendClient($_fno,'TMUX = '.Dumper($self->[OBJ_TMUX]). CRLF . 'DONE' . CRLF);
	}
	elsif ( $cmd =~ /^auth (.+)\s(.+)$/o ) {
	    my ($_u, $_p) = ($1, $2);
	    $self->_sendClient($_fno,'INFO Authentication<'.$_u.'>');
	    $self->__auth_dispatch($_fno, $_u, $_p);
	}
	elsif ( $cmd =~ /^babie([sz])$/o ) {
	    my $z = $1;

	    my $_bs = $self->[OBJ_TMUX]->babies(($z eq 'z') ? 0 : $_fno);

	    if ( ! defined ( $_bs ) || !scalar(keys %{$_bs}) ) {
		$self->_sendClient($_fno,'0 BABIES'. CRLF);
	    }
	    else {
		my ($_out, $_c);
		foreach my $_baby (keys %{$_bs}) {
		    $_c++;
		    $_out .= 'BABY '.$_baby.' ['.join(",", @{$_bs->{$_baby}}).']'.
			( defined ( $_bs->{$_baby}[2] ) ? 'Status='.
			  join ("-", @{$_bs->{$_baby}[2]}) : '** No status' ).
			CRLF;
		}

		$self->_sendClient($_fno, $_c.' BABIES'. CRLF. $_out);
	    }

	}
	else {
	  $self->_sendClient($_fno, 'Invalid command/syntax.'."\r\n");  
	}
    }

    if ( ! $zz ) {
	$self->_sendClient($_fno, 'Unrecognizeable input data.'."\r\n");  
    }

    $_d->[T_INBUF_LEN] = 0;
    $_d->[T_INBUF_DATA] = '';

}

sub handler_in($$) {
    my ($self, $_fno) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.' handler_in('.$self.', '.$_fno.')');

    if ( defined ( $_d->[T_SERVER_I] ) ) {
	my $_nc = [];
	my $z = 0;
	
	while ( my $_addr = accept($_nc->[$z], $_d->[T_SERVER_I][I_SERVER_OBJ] ) ) {

	    my ($_nport, $_niaddr) = sockaddr_in(getpeername($_nc->[$z]));
	    my $_nip               = inet_ntoa($_niaddr);
	    my $_nfno              = fileno($_nc->[$z]);


	    $self->[OBJ_TMUX][$_nfno][$self->[SELF_ID]] = [];
	    my $_nd = $self->[OBJ_TMUX][$_nfno][$self->[SELF_ID]];

	    $_nd->[T_PEER_I][I_PEER_OBJ]  = $_nc->[$z];
	    $_nd->[T_PEER_I][I_PEER_ADDR] = $_nip;
	    $_nd->[T_PEER_I][I_PEER_PORT] = $_nport;
	    $_nd->[T_SEPR_CHAR] = ",";

	    $self->__debug(2,__PACKAGE__.':'.__LINE__.' handler_in() New client['.$_nfno.'] IP<'.$_nip.'> Port<'.$_nport.'>');

	    $self->[OBJ_TMUX]->add($self, $_nc->[$z], $_nfno);
	    $z++;
	}

	if ( my $eno = POSIX::errno ) {
	    $self->__debug(2,__PACKAGE__.':'.__LINE__.' handler_in() - STOP<'.$eno.'> = '.POSIX::strerror($eno));
	}

	return(0);
    }

    my ($tRead, $b) = (0, 0);

    if ( ! defined ( $_d ) ) {
	$_d->[T_INBUF_LEN] = 0;
	$_d->[T_INBUF_DATA] = '';
    }

    while ( ( $b = sysread( $_d->[T_PEER_I][I_PEER_OBJ], $_d->[T_INBUF_DATA], 8192, $_d->[T_INBUF_LEN] )) > 0 ) {

	$self->__debug(5,$_fno, 'Socket '.$_fno.' += '.$b.' DATA: '.t_fmt_ascii($_d->[T_INBUF_DATA]));
	$tRead += $b;
	$_d->[T_INBUF_LEN] += $b;
	
	last if $b < 8192;;
	
    }
 
    $self->_process($_fno) if defined($tRead) && $tRead > 0;
   
    if ( defined($b) && $b == 0 && !$tRead ) {
	$self->_closeClient($_fno);
    }

    return(0);

}

sub handler_out($$) {
    my ($self, $_fno) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.' handler_out('.$self.', '.$_fno.')');

    my $_wb = syswrite($_d->[T_PEER_I][I_PEER_OBJ], $_d->[T_OUTBUF_DATA], $_d->[T_OUTBUF_LEN]);

    $self->__debug(5,$_fno, 'WB='.$_wb.' vs '.$_d->[T_OUTBUF_LEN]);

    if ( defined ( $_wb ) ) {
                    
	if($_wb == $_d->[T_OUTBUF_LEN]) {
	    $_d->[T_OUTBUF_DATA] = '';
	    $_d->[T_OUTBUF_LEN] = 0;

	    $self->[OBJ_TMUX]->mOUT($_fno, 0);

	}
	else {
	    $_d->[T_OUTBUF_DATA] = substr(  $_d->[T_OUTBUF_DATA], $_wb );
	}
    }

    return(0);
}

sub handler_err($$) {
    my ($self, $_fno) = (@_);

    $self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.' handler_out('.$self.', '.$_fno.')');

    $self->_closeClient($_fno, $!);

    return(0);
}

sub __load_authenticators($$) {
    my ($self, $_cc) = (@_);
    return -1 if !defined($_cc) || !$_cc;
    my $_lc = 0;

    if ( $self->[AUTH_TYPE] == A_TYPE_MONGO ) {
	for(my $x=1;$x<=$_cc;$x++) {
	    my $_nfno = $self->[OBJ_TMUX]->addTCPConnector('TMongoClient',
							   $self->[AUTH_HOST],
							   $self->[AUTH_PORT]);
	    
	    if ( defined ( $_nfno ) && $_nfno > 0 ) {
		$self->[OBJ_TMUX]->adopt(0, $_nfno, $self, '__callback_auth_mongo_connect');
		$self->[C_AUTH_M]{$_nfno} = $x;
		$self->[OBJ_TMUX]->mNick($_nfno, '$__AUTH_'.$x.'');
		$_lc++;
		$self->__debug(5, 0, 'Added MongoDB Authenticator['.$x.'] at<'.$_nfno.'>');
	    }
	}
    }
    return $_lc;
}


sub new {
    my $class = shift;
    my ($opts) = shift;
    my $self = [];
    bless $self, $class;

    $self->[DEBUG_LVL] = ( defined($opts->{'debug'}) ? $opts->{'debug'} : 0 );
    $self->[DEBUG_FNC] = ( $self->[DEBUG_LVL] > 0 && defined($opts->{'debugFunc'}) ) ? $opts->{'debugFunc'} : undef ;

    $self->[OBJ_TMUX]  = ( defined($opts->{'tmux'}) ? $opts->{'tmux'} : 0 );

    if ( defined ( $opts->{'MongoAuthenticateHost'} ) && defined ( $opts->{'MongoAuthenticatePort'} ) ) {
	$self->[AUTH_TYPE] = A_TYPE_MONGO;
	$self->[AUTH_HOST] = $opts->{'MongoAuthenticateHost'};
	$self->[AUTH_PORT] = $opts->{'MongoAuthenticatePort'};
	$self->__load_authenticators(10);
    }

    $self->__debug(2, 0, '__INITIALIZE__','OK');

    return $self;
}

1;
