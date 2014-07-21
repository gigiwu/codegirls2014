#!/usr/local/bin/perl

#┌─────────────────────────────────
#│ LOG IN : check.cgi - 2014/02/09
#│ copyright (c) KentWeb
#│ http://www.kent-web.com/
#└─────────────────────────────────

# モジュール宣言
use strict;
use CGI::Carp qw(fatalsToBrowser);

# 外部ファイル取り込み
require './init.cgi';
my %cf = init();

print <<EOM;
Content-type: text/html; charset=shift_jis

<html>
<head>
<meta http-equiv="content-type" content="text/html; charset=shift_jis">
<title>Check Mode</title>
</head>
<body>
<b>Check Mode: [ $cf{version} ]</b>
<ul>
EOM

# 隠しファイル
if ($cf{secfile} !~ /^https?\:\/\//) {
	if (-f $cf{secfile}) {
		print "<li>隠しファイルパス : OK\n";
	} else {
		print "<li>隠しファイルパス : NG\n";
	}
}

# テンプレート
foreach (qw(enter error)) {
	if (-f "$cf{tmpldir}/$_.html") {
		print "<li>テンプレート( $_.html ) : OK\n";
	} else {
		print "<li>テンプレート( $_.html ) : NG\n";
	}
}

print <<EOM;
</ul>
</body>
</html>
EOM
exit;

