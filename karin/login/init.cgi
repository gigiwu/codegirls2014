# ���W���[���錾
use strict;
my %cf;
#��������������������������������������������������������������������
#�� LOG IN : init.cgi - 2014/02/09
#�� copyright (c) KentWeb
#�� http://www.kent-web.com/
#��������������������������������������������������������������������
$cf{version} = 'Login v3.0';
#��������������������������������������������������������������������
#�� [���ӎ���]
#�� 1. ���̃v���O�����̓t���[�\�t�g�ł��B���̃v���O�������g�p����
#��    �����Ȃ鑹�Q�ɑ΂��č�҂͈�؂̐ӔC�𕉂��܂���B
#�� 2. �ݒu�Ɋւ��鎿��̓T�|�[�g�f���ɂ��肢�������܂��B
#��    ���ڃ��[���ɂ�鎿��͈�؂��󂯂������Ă���܂���B
#��������������������������������������������������������������������

#===========================================================
# �� �ݒ荀��
#===========================================================

# �����p�X���[�h
$cf{password} = 'kghsarchery';

# �B���t�@�C���y�T�[�o�p�X�z
$cf{secfile} = 'menu03.html';

# �{�̃v���O����URL�yURL�p�X�z
$cf{login_cgi} = './login.cgi';

# ���O�A�E�g���URL�yURL�p�X�z
# �� http://����L�q���Ă��悢
$cf{logout_url} = './login.cgi';

# �e���v���[�g�f�B���N�g���y�T�[�o�p�X�z
$cf{tmpldir} = './tmpl';

# �P�x�̓��e�Ŏ󗝂ł���ő�T�C�Y (bytes)
# �� 102400Byte = 100KB
$cf{maxdata} = 10240;

# �p�X���[�h�ۑ��p�Í��L�[
# �� �K���ɕύX���Ă��������B
$cf{crypt_key} = '57Y0xVqK';

#===========================================================
# �� �ݒ芮��
#===========================================================

# �ݒ�l��Ԃ�
sub init {
	return %cf;
}


1;
