#	$OpenBSD: connect-privsep.sh,v 1.8 2016/11/01 13:43:27 tb Exp $
#	Placed in the Public Domain.

tid="proxy connect with privsep"

cp $OBJ/sshd_proxy $OBJ/sshd_proxy.orig
echo 'UsePrivilegeSeparation yes' >> $OBJ/sshd_proxy

for p in ${SSH_PROTOCOLS}; do
	echo "= UsePrivilegeSeparation yes, protocol $p" >> $TEST_SSH_LOGFILE
	${SSH} -$p -F $OBJ/ssh_proxy 999.999.999.999 true
	if [ $? -ne 0 ]; then
		fail "ssh privsep+proxyconnect protocol $p failed"
	fi
done

cp $OBJ/sshd_proxy.orig $OBJ/sshd_proxy
echo 'UsePrivilegeSeparation sandbox' >> $OBJ/sshd_proxy

for p in ${SSH_PROTOCOLS}; do
	echo "= UsePrivilegeSeparation sandbox, protocol $p" >> $TEST_SSH_LOGFILE
	${SSH} -$p -F $OBJ/ssh_proxy 999.999.999.999 true
	if [ $? -ne 0 ]; then
		# XXX replace this with fail once sandbox has stabilised
		warn "ssh privsep/sandbox+proxyconnect protocol $p failed"
	fi
done

# Because sandbox is sensitive to changes in libc, especially malloc, retest
# with every malloc.conf option (and none).
if [ -z "TEST_MALLOC_OPTIONS" ]; then
	mopts="C F G J R S U X < >"
else
	mopts=`echo $TEST_MALLOC_OPTIONS | sed 's/./& /g'`
fi
# Skip tests as sandbox is not stabilized yet and the tested malloc
# options are OpenBSD specific.
: || \
for m in '' $mopts ; do
    for p in ${SSH_PROTOCOLS}; do
	env MALLOC_OPTIONS="$m" ${SSH} -$p -F $OBJ/ssh_proxy 999.999.999.999 true
	if [ $? -ne 0 ]; then
		fail "ssh privsep/sandbox+proxyconnect protocol $p mopt '$m' failed"
	fi
    done
done
