#	Placed in the Public Domain.

# NOTE: sandbox is not stabilised yet so just warn bellow
tid="proxy connect with privsep in FIPS mode"


cp $OBJ/sshd_proxy $OBJ/sshd_proxy.orig
echo 'UsePrivilegeSeparation yes' >> $OBJ/sshd_proxy

for p in 2 1; do
  echo "= UsePrivilegeSeparation yes, protocol $p" >> $TEST_SSH_LOGFILE

  $SSH -$p -F $OBJ/ssh_proxy 999.999.999.999 :
  if test 0 -ne $?; then
    if test 2 -eq $p ; then
      warn "ssh privsep+proxyconnect protocol $p failed"
    fi
  else
    if test 1 -eq $p ; then
      warn "ssh privsep+proxyconnect protocol $p failed"
    fi
  fi
done


cp $OBJ/sshd_proxy.orig $OBJ/sshd_proxy
echo 'UsePrivilegeSeparation sandbox' >> $OBJ/sshd_proxy

for p in 2 1; do
  echo "= UsePrivilegeSeparation sandbox, protocol $p" >> $TEST_SSH_LOGFILE

  $SSH -$p -F $OBJ/ssh_proxy 999.999.999.999 :
  if test 0 -ne $?; then
    if test 2 -eq $p ; then
      warn "ssh privsep/sandbox+proxyconnect protocol $p failed"
    fi
  else
    if test 1 -eq $p ; then
      warn "ssh privsep/sandbox+proxyconnect protocol $p failed"
    fi
  fi
done
