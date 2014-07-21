#!/usr/local/bin/perl

#��������������������������������������������������������������������
#�� LOG IN : login.cgi - 2014/02/09
#�� copyright (c) KentWeb
#�� http://www.kent-web.com/
#��������������������������������������������������������������������

# ���W���[���錾
use strict;
use CGI::Carp qw(fatalsToBrowser);
use lib "./lib";
use Crypt::RC4;

# �ݒ�t�@�C��
require './init.cgi';
my %cf = init();

# �f�[�^�󂯎��
my %in = parse_form();

# ��������
if ($in{mode} eq 'logout') { logout(); }
if ($in{login}) { login(); }
enter_form();

#-----------------------------------------------------------
#  ���O�C���F��
#-----------------------------------------------------------
sub login {
	# �F�؃G���[
	if ($in{pw} ne $cf{password}) { error("�F�؂ł��܂���"); }
	
	# �N�b�L�[�L��
	if ($in{cook} == 1) {
		set_cookie();
		
	# �N�b�L�[�폜
	} else {
		print "Set-Cookie: LoginID=; expires=Thu, 1-Jan-1970 00:00:00 GMT;\n";
	}

	# �t�@�C���w�肪URL�ł���� Locaion�w�b�_�ŃW�����v
	if ($cf{secfile} =~ m|^https?://|) {

		# �ړ�
		locat_url($cf{secfile});

	# HTML�̏ꍇ
	} else {

		# �`�F�b�N
		if (! -f $cf{secfile}) { error("�B���t�@�C�������݂��܂���"); }

		# �ǂݍ���
		open(IN,"$cf{secfile}") or error("open err: $cf{secfile}");
		print "Content-type: text/html\n\n";
		print <IN>;
		close(IN);
		exit;
	}
}

#-----------------------------------------------------------
#  �F�؉��
#-----------------------------------------------------------
sub enter_form {
	my $pw = get_cookie();

	# �e���v���[�g�ǂݍ���
	open(IN,"$cf{tmpldir}/enter.html") or error("open err: enter.html");
	my $tmpl = join('', <IN>);
	close(IN);

	# �u������
	$tmpl =~ s/!login_cgi!/$cf{login_cgi}/;
	$tmpl =~ s/!pw!/$pw/g;
	if ($pw ne '') {
		$tmpl =~ s|<input type="checkbox" name="cook"([^<>]+)>|<input type="checkbox" name="cook" checked="checked" $1>|;
	}
	
	# �\��
	print "Content-type: text/html; charset=shift_jis\n\n";
	footer($tmpl);
}

#-----------------------------------------------------------
#  �G���[����
#-----------------------------------------------------------
sub error {
	my $err = shift;

	open(IN,"$cf{tmpldir}/error.html") or die;
	my $tmpl = join('', <IN>);
	close(IN);

	$tmpl =~ s/!error!/$err/g;

	print "Content-type: text/html; charset=shift_jis\n\n";
	print $tmpl;
	exit;
}

#-----------------------------------------------------------
#  �t�b�^�[
#-----------------------------------------------------------
sub footer {
	my $foot = shift;

	# ���쌠�\�L�i�폜���ցj
	my $copy = <<EOM;
<p align="center" style="margin-top:3em;font-size:10px;font-family:verdana,helvetica,arial,osaka;">
- <a href="http://www.kent-web.com/" target="_top">Log in</a> -
</p>
EOM

	if ($foot =~ /(.+)(<\/body[^>]*>.*)/si) {
		print "$1$copy$2\n";
	} else {
		print "$foot$copy\n";
		print "</body></html>\n";
	}
	exit;
}

#-----------------------------------------------------------
#  �t�H�[���f�R�[�h
#-----------------------------------------------------------
sub parse_form {
	my ($buf,%in);
	if ($ENV{REQUEST_METHOD} eq "POST") {
		error('�󗝂ł��܂���') if ($ENV{CONTENT_LENGTH} > $cf{maxdata});
		read(STDIN, $buf, $ENV{CONTENT_LENGTH});
	} else {
		$buf = $ENV{QUERY_STRING};
	}
	foreach ( split(/&/, $buf) ) {
		my ($key,$val) = split(/=/);
		$val =~ tr/+/ /;
		$val =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("H2", $1)/eg;

		# �G�X�P�[�v
		$val =~ s/&/&amp;/g;
		$val =~ s/</&lt;/g;
		$val =~ s/>/&gt;/g;
		$val =~ s/"/&quot;/g;
		$val =~ s/'/&#39;/g;
		$val =~ s/[\r\n]//g;

		$in{$key} = $val;
	}
	return %in;
}

#-----------------------------------------------------------
#  ���O�A�E�g
#-----------------------------------------------------------
sub logout {
	# �ړ�
	locat_url($cf{logout_url});
}

#-----------------------------------------------------------
#  URL�ړ�
#-----------------------------------------------------------
sub locat_url {
	my $url = shift;

	if ($ENV{PERLXS} eq "PerlIS") {
		print "HTTP/1.0 302 Temporary Redirection\r\n";
		print "Content-type: text/html\n";
	}
	print "Location: $url\n\n";
	exit;
}

#-----------------------------------------------------------
#  �p�X���[�h�L��
#-----------------------------------------------------------
sub set_cookie {
	# RC4�Í��ϊ�
	my $crypt = RC4($cf{crypt_key},$in{pw});

	# �o�C�i����16�i��
	$crypt =~ s/(.)/unpack('H2',$1)/eg;
	$crypt =~ s/\n/n/g;

	# 60���ԗL��
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,undef,undef) = gmtime(time + 60*24*60*60);
	my @mon  = qw|Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec|;
	my @week = qw|Sun Mon Tue Wed Thu Fri Sat|;

	# �����t�H�[�}�b�g
	my $gmt = sprintf("%s, %02d-%s-%04d %02d:%02d:%02d GMT",
				$week[$wday],$mday,$mon[$mon],$year+1900,$hour,$min,$sec);

	print "Set-Cookie: LoginID=$crypt; expires=$gmt\n";
}

#-----------------------------------------------------------
#  �p�X���[�h�擾
#-----------------------------------------------------------
sub get_cookie {
	# �N�b�L�[�擾
	my $cook = $ENV{HTTP_COOKIE};

	# �Y��ID�����o��
	my %cook;
	foreach ( split(/;/, $cook) ) {
		my ($key,$val) = split(/=/);
		$key =~ s/\s//g;
		$cook{$key} = $val;
	}
	$cook{LoginID} =~ s/\W//g;

	# �o�C�i���֖߂�
	$cook{LoginID} =~ s/n/\n/g;
	$cook{LoginID} =~ s/([0-9A-Fa-f]{2})/pack('H2',$1)/eg;

	# RC4�Í��ϊ�
	return RC4($cf{crypt_key},$cook{LoginID});
}

