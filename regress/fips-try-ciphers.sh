#	Placed in the Public Domain.

tid="try ciphers in FIPS mode"

fips_ciphers="
  aes128-cbc aes192-cbc aes256-cbc rijndael-cbc@lysator.liu.se
  3des-cbc
"
config_defined OPENSSL_HAVE_EVPCTR &&
  fips_ciphers="$fips_ciphers
  aes128-ctr aes192-ctr aes256-ctr
"
ciphers="
  blowfish-cbc cast128-cbc
  arcfour128 arcfour256 arcfour
"


fips_macs="hmac-sha1 hmac-sha1-96"
config_defined HAVE_EVP_SHA256 &&
  fips_macs="$fips_macs
  hmac-sha2-256 hmac-sha2-512
"
macs="
  hmac-md5 umac-64@openssh.com hmac-md5-96
"

cp $OBJ/sshd_proxy $OBJ/sshd_proxy_bak

update_sshd_proxy() {
  cp $OBJ/sshd_proxy_bak $OBJ/sshd_proxy
  echo "Ciphers=$1" >> $OBJ/sshd_proxy
  echo "MACs=$2"    >> $OBJ/sshd_proxy
}


for c in $fips_ciphers; do
  for m in $fips_macs; do
    msg="proto 2 fips-cipher $c fips-mac $m"
    trace "$msg"
    verbose "test $tid: $msg"
    update_sshd_proxy $c $m
    $SSH -F $OBJ/ssh_proxy -2 -m $m -c $c somehost :
    if test 0 -ne $?; then
      fail "ssh -2 failed with mac $m cipher $c"
    fi
  done
done

# non-fips mac should fail
for c in $fips_ciphers; do
  for m in $macs; do
    msg="proto 2 fips-cipher $c mac $m"
    trace "$msg"
    verbose "negative test $tid: $msg"
    update_sshd_proxy $c $m
    $SSH -F $OBJ/ssh_proxy -2 -m $m -c $c somehost : >>$TEST_SSH_LOGFILE 2>&1
    if test 0 -eq $?; then
      fail "ssh -2 succeeded with mac $m cipher $c - nok"
    fi
  done
done

# non-fips cipher should fail
for c in $ciphers; do
  for m in $fips_macs $macs; do
    msg="proto 2 cipher $c mac $m"
    trace "$msg"
    verbose "negative test $tid: $msg"
    update_sshd_proxy $c $m
    $SSH -F $OBJ/ssh_proxy -2 -m $m -c $c somehost : >>$TEST_SSH_LOGFILE 2>&1
    if test 0 -eq $?; then
      fail "ssh -2 succeeded with mac $m cipher $c - nok"
    fi
  done
done

# protocol 1 should fail
ciphers="3des blowfish"
for c in $ciphers; do
  msg="proto 1 cipher $c"
  trace "$msg"
  verbose "negative test $tid: $msg"
  update_sshd_proxy $c $m
  $SSH -F $OBJ/ssh_proxy -1 -c $c somehost : >>$TEST_SSH_LOGFILE 2>&1
  if test 0 -eq $?; then
    fail "ssh -1 succeeded with cipher $c - nok"
  fi
done
