#!/usr/local/bin/perl

#┌─────────────────────────────────
#│ LOG IN : login.cgi - 2014/02/09
#│ copyright (c) KentWeb
#│ http://www.kent-web.com/
#└─────────────────────────────────

# モジュール宣言
use strict;
use CGI::Carp qw(fatalsToBrowser);
use lib "./lib";
use Crypt::RC4;

# 設定ファイル
require './init.cgi';
my %cf = init();

# データ受け取り
my %in = parse_form();

# 処理分岐
if ($in{mode} eq 'logout') { logout(); }
if ($in{login}) { login(); }
enter_form();

#-----------------------------------------------------------
#  ログイン認証
#-----------------------------------------------------------
sub login {
	# 認証エラー
	if ($in{pw} ne $cf{password}) { error("認証できません"); }
	
	# クッキー記憶
	if ($in{cook} == 1) {
		set_cookie();
		
	# クッキー削除
	} else {
		print "Set-Cookie: LoginID=; expires=Thu, 1-Jan-1970 00:00:00 GMT;\n";
	}

	# ファイル指定がURLであれば Locaionヘッダでジャンプ
	if ($cf{secfile} =~ m|^https?://|) {

		# 移動
		locat_url($cf{secfile});

	# HTMLの場合
	} else {

		# チェック
		if (! -f $cf{secfile}) { error("隠しファイルが存在しません"); }

		# 読み込み
		open(IN,"$cf{secfile}") or error("open err: $cf{secfile}");
		print "Content-type: text/html\n\n";
		print <IN>;
		close(IN);
		exit;
	}
}

#-----------------------------------------------------------
#  認証画面
#-----------------------------------------------------------
sub enter_form {
	my $pw = get_cookie();

	# テンプレート読み込み
	open(IN,"$cf{tmpldir}/enter.html") or error("open err: enter.html");
	my $tmpl = join('', <IN>);
	close(IN);

	# 置き換え
	$tmpl =~ s/!login_cgi!/$cf{login_cgi}/;
	$tmpl =~ s/!pw!/$pw/g;
	if ($pw ne '') {
		$tmpl =~ s|<input type="checkbox" name="cook"([^<>]+)>|<input type="checkbox" name="cook" checked="checked" $1>|;
	}
	
	# 表示
	print "Content-type: text/html; charset=shift_jis\n\n";
	footer($tmpl);
}

#-----------------------------------------------------------
#  エラー処理
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
#  フッター
#-----------------------------------------------------------
sub footer {
	my $foot = shift;

	# 著作権表記（削除厳禁）
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
#  フォームデコード
#-----------------------------------------------------------
sub parse_form {
	my ($buf,%in);
	if ($ENV{REQUEST_METHOD} eq "POST") {
		error('受理できません') if ($ENV{CONTENT_LENGTH} > $cf{maxdata});
		read(STDIN, $buf, $ENV{CONTENT_LENGTH});
	} else {
		$buf = $ENV{QUERY_STRING};
	}
	foreach ( split(/&/, $buf) ) {
		my ($key,$val) = split(/=/);
		$val =~ tr/+/ /;
		$val =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("H2", $1)/eg;

		# エスケープ
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
#  ログアウト
#-----------------------------------------------------------
sub logout {
	# 移動
	locat_url($cf{logout_url});
}

#-----------------------------------------------------------
#  URL移動
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
#  パスワード記憶
#-----------------------------------------------------------
sub set_cookie {
	# RC4暗号変換
	my $crypt = RC4($cf{crypt_key},$in{pw});

	# バイナリを16進へ
	$crypt =~ s/(.)/unpack('H2',$1)/eg;
	$crypt =~ s/\n/n/g;

	# 60日間有効
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,undef,undef) = gmtime(time + 60*24*60*60);
	my @mon  = qw|Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec|;
	my @week = qw|Sun Mon Tue Wed Thu Fri Sat|;

	# 時刻フォーマット
	my $gmt = sprintf("%s, %02d-%s-%04d %02d:%02d:%02d GMT",
				$week[$wday],$mday,$mon[$mon],$year+1900,$hour,$min,$sec);

	print "Set-Cookie: LoginID=$crypt; expires=$gmt\n";
}

#-----------------------------------------------------------
#  パスワード取得
#-----------------------------------------------------------
sub get_cookie {
	# クッキー取得
	my $cook = $ENV{HTTP_COOKIE};

	# 該当IDを取り出す
	my %cook;
	foreach ( split(/;/, $cook) ) {
		my ($key,$val) = split(/=/);
		$key =~ s/\s//g;
		$cook{$key} = $val;
	}
	$cook{LoginID} =~ s/\W//g;

	# バイナリへ戻す
	$cook{LoginID} =~ s/n/\n/g;
	$cook{LoginID} =~ s/([0-9A-Fa-f]{2})/pack('H2',$1)/eg;

	# RC4暗号変換
	return RC4($cf{crypt_key},$cook{LoginID});
}

